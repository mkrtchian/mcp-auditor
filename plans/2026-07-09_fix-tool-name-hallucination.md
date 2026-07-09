# Fix tool_name hallucination in generated payloads

## Context

During a CVE benchmark trace against `server-filesystem` (tool `read_file`), the
attack generator's structured output sometimes copies the **category** string
into `AuditPayload.tool_name` instead of the real tool name. `execute_tool` then
dispatches on that value:

```python
response = await mcp_client.call_tool(case.payload.tool_name, case.payload.arguments)
```

so the call becomes `call_tool("injection", ...)` and the server replies
`Error: Unknown tool: injection`. Those cases never exercise the tool under audit.

The failure is stochastic and bimodal per generation run: most runs are clean,
a minority are catastrophic (the model mode-locks from the first improvised
category onward and keeps copying the category into `tool_name` for the rest of
the run). The aggregate rate hides this all-or-nothing structure.

Root cause: `tool_name` is **redundant** for dispatch everywhere. The tool under
audit is already fixed as `current_tool` (set by `prepare_tool`). Having the LLM
also emit `tool_name` adds a field with no decision value that invites the
hallucination. The chain path already works around this defensively
(`execute_step` overwrites `payload.tool_name` with `tool.name` before calling),
which confirms the value is never a genuine tool-selection choice, even in chains.

The same redundancy exists on the judge side: `EvalResult` is produced by the
judge LLM and forces it to re-emit `tool_name`, `category`, and `payload`, all of
which are already known in code from `current_tool` and the case being judged.
Re-emitting them is a second, lower-stakes hallucination surface.

## Approach

Remove the redundant identity fields from what the LLM must produce, and let code
own identity and dispatch. Two moves:

1. **Generator side**: drop `tool_name` from `AuditPayload`. Dispatch always uses
   `current_tool.name`.
2. **Judge side**: introduce a narrow `Judgment` value object that the judge emits
   (`verdict`, `justification`, `severity`). Assemble `EvalResult` in code,
   stamping `tool_name`, `category`, and `payload` from the known context. The
   judge no longer re-emits identity.

`EvalResult` keeps all six fields (`tool_name`, `category`, `payload`, `verdict`,
`justification`, `severity`), so nothing downstream of the judge (export, eval
metrics, rendering, findings) changes shape. Only the *source* of the identity
fields moves from the LLM to code.

## Files to modify

### `src/mcp_auditor/domain/models.py`

- `AuditPayload`: remove the `tool_name: str` field. New shape:
  ```python
  class AuditPayload(BaseModel):
      category: AuditCategory
      description: str = Field(description="What this test case verifies")
      arguments: dict[str, Any]
  ```
- Add a new value object for the judge output:
  ```python
  class Judgment(BaseModel):
      """The judge's verdict, decoupled from the identity fields the code owns."""

      verdict: EvalVerdict
      justification: str
      severity: Severity
  ```
- `EvalResult`: unchanged in shape. It is now assembled in code, not emitted by
  the LLM.

Naming note: the model is called `Judgment` (not `Verdict`) to avoid stutter with
the existing `EvalVerdict` enum and the `EvalResult.verdict` field. `judgment.verdict`
reads cleanly.

### `src/mcp_auditor/graph/nodes.py`

- Import `Judgment` alongside the existing `EvalResult` import (`EvalResult` is
  still used, now assembled in code).
- `execute_tool`: dispatch on the current tool, not the payload.
  ```python
  tool = state["current_tool"]
  response = await mcp_client.call_tool(tool.name, case.payload.arguments)
  ```
- `judge_response`: request `Judgment`, assemble `EvalResult` in code.
  ```python
  judgment, usage = await llm.generate_structured(prompt, Judgment)
  eval_result = EvalResult(
      tool_name=tool.name,
      category=case.payload.category,
      payload=case.payload.arguments,
      verdict=judgment.verdict,
      justification=judgment.justification,
      severity=judgment.severity,
  )
  judged_case = case.model_copy(update={"eval_result": eval_result})
  ```
  (`tool` is already bound from `state["current_tool"]`.)

### `src/mcp_auditor/graph/chain_nodes.py`

- Import `Judgment` from `domain.models` (the new judge output). `ChainGoal` and
  `ChainStep` are already imported / not needed, since the chain-payload logic is
  inline in `judge_chain` rather than a typed helper.
- `execute_step`: drop the now-dead defensive copy, dispatch on `tool.name`.
  ```python
  payload: AuditPayload = state["current_step_payload"]
  tool = state["current_tool"]
  response = await mcp_client.call_tool(tool.name, payload.arguments)
  ```
- `judge_chain`: request `Judgment`, assemble `EvalResult` in code. The chain
  payload is chosen inline (single caller, 3-line if/else, no helper): the last
  executed step's arguments, falling back to the goal's `first_step` arguments if
  the step list is empty (see Edge cases for the decision).
  ```python
  judgment, usage = await llm.generate_structured(prompt, Judgment)
  payload = steps[-1].payload.arguments if steps else goal.first_step.arguments
  eval_result = EvalResult(
      tool_name=tool.name,
      category=goal.category,
      payload=payload,
      verdict=judgment.verdict,
      justification=judgment.justification,
      severity=judgment.severity,
  )
  judged_chain = chain.model_copy(update={"eval_result": eval_result})
  ```
  (`ChainGoal` no longer needs importing for a helper annotation, since the logic
  is inline. `Judgment` still must be imported.)
- `plan_step` still generates an `AuditPayload` via `generate_structured`. With
  `tool_name` gone from the schema, no code change is needed there beyond the
  model change, but its prompt must stop asking for `tool_name` (see chain_prompts).

### `src/mcp_auditor/graph/prompts.py`

- `build_attack_generation_prompt`: remove the output-field line
  `- tool_name: the name of the tool to call`. This is the mode-lock trigger.
  The remaining fields become `category`, `description`, `arguments`.
- `build_judge_prompt`: the output instruction already says
  "Provide a justification and severity" and to decide FAIL/PASS. No `tool_name`
  or `category` is requested in the output, so no change is needed to the emitted
  fields. Confirm the wording still matches a `Judgment` (verdict + justification
  + severity).

### `src/mcp_auditor/graph/chain_prompts.py`

- `build_step_planning_prompt` / the `first_step` description in
  `build_chain_planning_prompt`: neither prompt currently spells out a `tool_name`
  bullet (they reference "AuditPayload" / "first_step" generically), so no wording
  change is required here beyond the model change. Only edit if a future reading
  finds an explicit `tool_name` field instruction.
- `build_chain_judge_prompt`: remove the sentence
  "For the payload field, use the arguments from the most significant step in the
  chain." The judge no longer emits `payload`.

### `src/mcp_auditor/stream_handler.py`

- The progress display reads `pending[0].payload.tool_name`, which no longer
  exists. Track the current tool name from the `prepare_tool` orchestrator event
  (which already receives `current_tool`) and use it in the
  `generate_test_cases` branch:
  ```python
  # in _on_orchestrator_event, prepare_tool branch:
  if tool:
      self._tool_index += 1
      self._current_tool_name = tool.name
  # in _on_tool_audit_event, generate_test_cases branch:
  progress = self._display.create_tool_progress(
      self._tool_index, self._tool_count, self._current_tool_name, len(pending)
  )
  ```
  Initialize `self._current_tool_name = ""` in `__init__`.

### `evals/run_judge_eval.py`

This judge-isolation harness reuses `build_judge_prompt` and judges with the same
LLM contract as `judge_response`, so it must move to `Judgment` too.

- `_parse_case` (line ~104): the `AuditPayload(...)` construction drops the
  `tool_name=entry["tool_name"]` argument. Under pyright strict this is a
  **blocking** failure otherwise (`tool_name` is no longer a model field, so it is
  flagged as an unknown keyword argument). `ToolDefinition(name=entry["tool_name"])`
  above it is unaffected and stays.
- `_judge_all_cases` (line ~79): change
  `eval_result, _ = await llm.generate_structured(prompt, EvalResult)` to request
  `Judgment`, and read `judgment.verdict` / `judgment.justification` when building
  `JudgedCase`. Keeping `EvalResult` here would re-introduce the exact identity
  re-emission surface this plan removes on the judge side. `EvalResult` has no
  other use in this file, so swap the import on line ~23 (`EvalResult` ->
  `Judgment`).
- No fixture-file change is needed: the JSON fixtures still carry `tool_name` for
  building the `ToolDefinition`, and `Judgment` does not read it.

## What stays unchanged

- `EvalResult` **field set** (all six fields) and the shape consumed by export
  (`judged_cases.jsonl`), eval metrics (recall/precision keyed on
  `(tool_name, category)`), console findings, and `AuditReport.findings`. The
  metrics and export do not read `EvalResult.payload`, so recall/precision are
  unaffected.
- The judge's decision logic and prompt intent (scoped to one category, judge
  observed behavior, charitable reading via stated purpose).
- The generation flow, routing, reducers, checkpointing, and the graph topology.
- The CLI, environment variables, and the dry-run display (which already takes the
  tool name from `report.tool.name`, not from the payload).
- `ChainGoal`, `ChainStep`, `StepObservation`, `AttackChain` shapes.

### Behavior that does change (acknowledged, benign-to-positive)

- The markdown report's `**Payload**:` line (`domain/rendering.py:100`, the sole
  reader of `EvalResult.payload`) changes content for **both** finding types.
  Today that value is whatever the judge LLM happened to fill (the judge prompt
  never asks for it). After this change it is code-stamped: the actual attack
  `arguments` for single-step findings (an accuracy improvement), and the last
  executed step's arguments for chains (see the chain-payload decision in Edge
  cases). Shape is unchanged, so nothing downstream of rendering is affected. This
  is a deliberate, minor change to a human-readable line, not a regression.

## Edge cases

- **Chain `EvalResult.payload`**: previously the judge chose "the arguments from
  the most significant step". With `payload` no longer judge-emitted, code picks a
  deterministic representative: the last executed step's arguments, falling back
  to the goal's `first_step` arguments if the step list is empty. This is a
  deliberate behavior change (deterministic over judge-selected). The full chain
  progression is still visible in the rendered report, so no information is lost
  to the reader.
- **A tool literally named after a category** (for example a tool called
  `injection`): irrelevant now, since dispatch never reads a category-derived
  value. Dispatch is always `current_tool.name`.
- **Empty pending cases in stream_handler**: the `generate_test_cases` branch
  already guards `if pending:`, so `_current_tool_name` is only read when there is
  something to display.

## Test scenarios

Follow the project's test-first workflow: write the red test first, confirm it
fails on current code, then implement.

1. **Dispatch uses `current_tool.name`, not the payload (red first, then evolve)**
   - Two-phase, because removing the field is itself what kills the vector, so no
     single test body is both red-on-old and compilable-on-new:
     - **Red (transient)**: on current code, build a case with
       `AuditPayload(tool_name="injection", ...)` diverging from
       `current_tool = read_file`, run `execute_tool`, assert the `FakeMCPClient`
       recorded a call to `read_file`. This fails today (records `"injection"`),
       proving the bug.
     - **Enduring**: after removing the field, that construction no longer
       compiles. Rewrite the test to its durable form: given `current_tool =
       read_file`, `execute_tool` records a call to `read_file`. Post-fix this is a
       characterization/guard test (a wrong payload tool name is no longer
       expressible), so the real protection is structural, the type system. The
       guard still catches a future regression that re-points dispatch elsewhere.
2. **Judge output is a `Judgment`, EvalResult is stamped in code**
   - Given a `FakeLLM` queued with a `Judgment(verdict=FAIL, ...)` and
     `current_tool = read_file`, category `injection`, when `judge_response` runs,
     then the resulting `EvalResult` has `tool_name == "read_file"`,
     `category == injection`, and `payload == case.payload.arguments`, with the
     verdict, justification, and severity taken from the `Judgment`.
3. **Chain judge stamps identity and a deterministic payload**
   - Given a completed chain with two steps and a queued `Judgment(FAIL)`, when
     `judge_chain` runs, then `EvalResult.tool_name == current_tool.name`,
     `category == goal.category`, and `payload == last_step.arguments`.
4. **Generation prompt no longer mentions tool_name**
   - `build_attack_generation_prompt` output does not contain `tool_name`.
   - `build_chain_judge_prompt` output does not contain "most significant step".
5. **End-to-end graph run still produces findings**
   - Existing `test_graph` behavior tests pass with fixtures updated: any
     `FakeLLM` that previously queued an `EvalResult` for a judge call now queues
     a `Judgment`. `AuditPayload(...)` constructions drop `tool_name`.

### Fixture updates (mechanical)

- `AuditPayload(tool_name=..., ...)` constructions across `tests/unit/support/*`
  and `tests/unit/*`: remove the `tool_name` argument and the `tool_name`
  parameter from the given-helpers (`a_payload`, `a_test_case`, `a_tool_report`,
  and equivalents in `test_models_given`, `test_nodes_given`,
  `test_chain_nodes_given`, `test_graph_given`, `test_rendering_given`,
  `test_export_given`, `test_console_given`, `test_eval_metrics_given`,
  `test_cve_oracle_given`, `test_prompts_given`).
- Any `FakeLLM([... EvalResult(...) ...])` where the `EvalResult` stands in for a
  judge call: replace with `Judgment(...)`. `FakeLLM` enforces the schema via
  `isinstance`, so a leftover `EvalResult` in a judge slot raises `TypeError` and
  makes the miss obvious.
- `EvalResult(...)` constructions that build expected/report data (not judge
  stand-ins) keep `tool_name` and stay as is, but their nested
  `payload=AuditPayload(tool_name=...)` loses the `tool_name` argument.

## Verification

```bash
uv run pytest tests/unit          # unit suite, fakes
uv run pytest tests/integration   # real MCP server, no LLM
uv run ruff check .
uv run ruff format --check .
uv run pyright                    # strict mode
```

`pyright` strict catches missed `tool_name` references at **explicit-keyword**
sites (`AuditPayload(tool_name=...)`, `.payload.tool_name`). It does **not** catch
the one dict-unpack construction, `test_models_given.py:31`
(`AuditPayload(**(defaults | overrides))`): `AuditPayload` has no
`model_config`, so pydantic v2's default `extra="ignore"` silently drops a
leftover `"tool_name"` key in the `defaults` dict rather than raising. So finish
the sweep with a grep, not just the type checker:

```bash
grep -rn "tool_name" tests/ evals/ src/mcp_auditor   # every remaining hit must be an EvalResult field, a ToolDefinition name, or a fixture-JSON key — never an AuditPayload input
```

Manual confirmation on the original failure surface: run an audit against the
filesystem server and confirm no `Unknown tool: <category>` errors appear in the
tool responses, and that every case's `EvalResult.tool_name` equals the tool
actually audited.

## Not in scope

- Removing the redundant `category` re-derivation anywhere else.
- Changing the judge's category-scoping or charitable-reading rules.
- Any change to the generation guidance content (the DB-flavored per-category
  hints are a separate concern).
- Any new verdict value such as an abstention/unknown verdict.

## Implementation steps

Two steps. Step 1 removes `tool_name` from `AuditPayload` and moves dispatch to
`current_tool.name` (the large mechanical fixture sweep, atomic because the field
removal breaks every `AuditPayload(...)` construction at once under pyright
strict). Step 2 introduces the `Judgment` value object and assembles `EvalResult`
in code. After step 1 the suite is fully green with the judge still emitting
`EvalResult`, so it is a clean, committable state; step 2 builds on it.

Verification commands (from `CLAUDE.md`), run for **both** steps:

```bash
uv run pytest tests/unit
uv run pytest tests/integration
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

Follow the test-first workflow: write/adjust the red test, confirm it fails on
current code, then implement. Each step is one atomic commit.

### Step 1: Drop `tool_name` from `AuditPayload`, dispatch on `current_tool.name`

**Files** (production):
- `src/mcp_auditor/domain/models.py`
- `src/mcp_auditor/graph/nodes.py`
- `src/mcp_auditor/graph/chain_nodes.py`
- `src/mcp_auditor/graph/prompts.py`
- `src/mcp_auditor/stream_handler.py`
- `evals/run_judge_eval.py` (only `_parse_case`, line ~104)

**Files** (tests / fixtures — remove the `tool_name` argument from every
`AuditPayload(...)` construction and from any `tool_name` parameter of the
given-helpers `a_payload` / `a_test_case` / `a_tool_report` and equivalents):
- `tests/unit/support/test_models_given.py`, `test_nodes_given.py`,
  `test_chain_nodes_given.py`, `test_graph_given.py`, `test_rendering_given.py`,
  `test_export_given.py`, `test_console_given.py`, `test_eval_metrics_given.py`,
  `test_cve_oracle_given.py`, `test_prompts_given.py`
- Any direct `AuditPayload(...)` in `tests/unit/test_models.py`,
  `test_nodes.py`, `test_chain_nodes.py`, `test_chain_models.py`,
  `test_prompts.py`, `test_graph.py`, `test_export.py`, `test_chain_prompts.py`

**Do** (tests first):
1. Add the red test for dispatch (test scenario 1, two-phase). In `test_nodes.py`
   (+ its given/then): first the transient red form with a diverging
   `AuditPayload(tool_name="injection", ...)` against `current_tool = read_file`,
   confirmed failing on current code (it records `"injection"`). After step 3
   removes the field, rewrite it to the enduring form (given `current_tool =
   read_file`, `execute_tool` records a call to `read_file`), since the diverging
   construction no longer compiles.
2. Add the prompt test (test scenario 4, first half): in `test_prompts.py`,
   assert `build_attack_generation_prompt(...)` output does **not** contain
   `tool_name`.
3. `models.py`: remove `tool_name: str` from `AuditPayload`. New field set is
   `category`, `description`, `arguments` (see plan for the exact body).
   Do **not** touch `EvalResult` in this step (it keeps all six fields and is
   still LLM-emitted for now).
4. `nodes.py` `make_execute_tool`: dispatch on the current tool:
   `tool = state["current_tool"]`, then
   `response = await mcp_client.call_tool(tool.name, case.payload.arguments)`.
5. `chain_nodes.py` `make_execute_step`: delete the now-dead defensive copy
   (`if payload.tool_name != tool.name: ...`) and dispatch on `tool.name`:
   `response = await mcp_client.call_tool(tool.name, payload.arguments)`.
6. `prompts.py` `build_attack_generation_prompt`: remove the output-field line
   `- tool_name: the name of the tool to call`. Leave `build_judge_prompt`
   unchanged (verify its output asks only for verdict/justification/severity).
7. `stream_handler.py`: track the current tool name. Add
   `self._current_tool_name = ""` in `__init__`; in the `prepare_tool` branch set
   `self._current_tool_name = tool.name` when `tool` is present; in the
   `generate_test_cases` branch replace `pending[0].payload.tool_name` with
   `self._current_tool_name` (the `if pending:` guard already protects the read).
8. `evals/run_judge_eval.py` `_parse_case`: drop the
   `tool_name=entry["tool_name"]` argument from the `AuditPayload(...)`
   construction. Leave the `ToolDefinition(name=entry["tool_name"])` above it and
   the `_judge_all_cases` / `EvalResult` usage untouched (that moves in step 2).
   No fixture JSON change.
9. Mechanically remove the `tool_name` argument from every `AuditPayload(...)` in
   the test/fixture files listed above, and the `tool_name` parameter from the
   given-helpers. **Include the dict-unpack site**: in `test_models_given.py`
   `a_payload` uses `AuditPayload(**(defaults | overrides))` with a `"tool_name"`
   key in the `defaults` dict. Pydantic's default `extra="ignore"` swallows that
   key silently (no error, and pyright cannot see through `**dict`), so remove it
   by hand. Leave `EvalResult(...)` constructions (they keep `tool_name`) and
   `FakeLLM([... EvalResult(...) ...])` judge slots as-is for this step.

**Test**:
- `execute_tool` records a call to `read_file` (the `current_tool` name) even
  when the payload would have named a different/category value.
- `build_attack_generation_prompt` output contains no `tool_name`.
- Full existing unit/integration suites stay green with `AuditPayload` fixtures
  updated.

**Verify**: run the five commands above. `pyright` (strict) must report zero
errors — it catches any missed `.payload.tool_name` reference or leftover
`tool_name=` keyword on `AuditPayload`.

### Step 2: Introduce `Judgment`, assemble `EvalResult` in code

**Files** (production):
- `src/mcp_auditor/domain/models.py` (add `Judgment`)
- `src/mcp_auditor/graph/nodes.py` (`judge_response`)
- `src/mcp_auditor/graph/chain_nodes.py` (`judge_chain`)
- `src/mcp_auditor/graph/chain_prompts.py` (`build_chain_judge_prompt`)
- `evals/run_judge_eval.py` (`_judge_all_cases` + the line ~23 import)

**Files** (tests / fixtures — swap judge-slot `EvalResult(...)` for `Judgment(...)`
in the `FakeLLM` queues that stand in for a judge call):
- `tests/unit/test_nodes.py` (+ given/then), `tests/unit/test_chain_nodes.py`
  (+ given), `tests/unit/support/test_graph_given.py`, `tests/unit/test_graph.py`
- Leave `EvalResult(...)` constructions that build **expected/report** data
  (in `test_export_given.py`, `test_rendering_given.py`, `test_console_given.py`,
  `test_eval_metrics_given.py`, `test_cve_oracle_given.py`, `test_models*.py`)
  unchanged — those are not judge stand-ins.

**Do** (tests first):
1. Add red tests (test scenarios 2, 3, and 4 second half):
   - `test_nodes.py`: given a `FakeLLM` queued with `Judgment(verdict=FAIL, ...)`,
     `current_tool = read_file`, category `injection`, run `judge_response`, then
     the resulting `EvalResult` has `tool_name == "read_file"`,
     `category == injection`, `payload == case.payload.arguments`, and
     verdict/justification/severity taken from the `Judgment`.
   - `test_chain_nodes.py`: given a completed chain with two steps and a queued
     `Judgment(FAIL)`, run `judge_chain`, then `EvalResult.tool_name ==
     current_tool.name`, `category == goal.category`, `payload ==
     last_step.payload.arguments`.
   - `test_chain_prompts.py`: `build_chain_judge_prompt` output does **not**
     contain "most significant step".
   Confirm these fail on step-1 code (judge still emits `EvalResult`; `Judgment`
   does not yet exist / `FakeLLM` rejects it).
2. `models.py`: add the `Judgment` value object (`verdict: EvalVerdict`,
   `justification: str`, `severity: Severity`). `EvalResult` shape unchanged.
3. `nodes.py` `make_judge_response`: import `Judgment`; request `Judgment` from
   the LLM and assemble `EvalResult` in code, stamping `tool_name=tool.name`,
   `category=case.payload.category`, `payload=case.payload.arguments`, and the
   three judged fields from the `Judgment` (see plan snippet).
4. `chain_nodes.py` `make_judge_chain`: import `Judgment`; request `Judgment`,
   pick the deterministic payload inline (`steps[-1].payload.arguments if steps
   else goal.first_step.arguments`), assemble `EvalResult` stamping
   `tool_name=tool.name`, `category=goal.category`, that payload, and the judged
   fields.
5. `chain_prompts.py` `build_chain_judge_prompt`: remove the sentence "For the
   payload field, use the arguments from the most significant step in the chain."
6. `evals/run_judge_eval.py`: swap the line ~23 import `EvalResult -> Judgment`;
   in `_judge_all_cases` request `Judgment` from `generate_structured` and read
   `judgment.verdict` / `judgment.justification` when building `JudgedCase`.
7. In the judge-slot fixtures listed above, replace `EvalResult(...)` with
   `Judgment(...)` (only verdict/justification/severity). `FakeLLM` enforces the
   schema via `isinstance`, so a leftover `EvalResult` in a judge slot raises
   `TypeError` and surfaces any miss.

**Test**:
- `judge_response` produces an `EvalResult` with code-stamped identity
  (`read_file`, `injection`, `case.payload.arguments`) and judge-supplied
  verdict/justification/severity.
- `judge_chain` stamps `current_tool.name`, `goal.category`, and the last step's
  arguments as payload.
- `build_chain_judge_prompt` no longer mentions "most significant step".
- End-to-end `test_graph` behavior tests still produce findings with judge slots
  queuing `Judgment`.

**Verify**: run the five commands above; all green, `pyright` zero errors. Then
the manual confirmation from the plan's Verification section (audit against the
filesystem server: no `Unknown tool: <category>` errors, every case's
`EvalResult.tool_name` equals the tool audited).
