# Cross-tool learning (§10a)

**ADR:** `docs/adr/009-cross-tool-learning.md`

## Context

Each tool is audited in isolation. The generator for tool B doesn't know that tool A exposed `sqlite3.OperationalError` in its errors. A human pentester would use that signal to target SQLite specifically instead of generic SQL injection.

Cross-tool learning makes the graph stateful across tools: after auditing tool A, extract signals from the responses and feed them into the generator for tool B. The existing honeypot already has the perfect scenario — `get_user` leaks SQLite errors, and `execute_query` is vulnerable to SQL injection.

## Approach

Three changes:

1. **Tool ordering** — read-like tools first (they reveal more about the system without side effects).
2. **Context extraction** — a new LLM node after `finalize_tool_audit` that synthesizes what was learned from one tool's results.
3. **Context-aware generation** — the generation prompt receives accumulated context and adapts payloads accordingly.

The context extraction is a separate LLM call per tool (not merged with generation). This keeps responsibilities clean: extraction is backward-looking (what did we learn?), generation is forward-looking (what do we test?). The cost is one small LLM call per tool — acceptable overhead for testability and inspectability.

## Domain model: `AttackContext`

A lightly structured Value Object. Typed fields for high-value signals, free-text for the long tail.

```python
# src/mcp_auditor/domain/models.py

class AttackContext(BaseModel):
    """Accumulated intelligence from previous tool audits."""
    db_engine: str | None = None          # "sqlite", "postgresql", "mysql", ...
    framework: str | None = None          # "flask", "django", "express", ...
    language: str | None = None           # "python", "javascript", "go", ...
    exposed_internals: list[str] = []     # paths, table names, config keys
    effective_payloads: list[str] = []    # descriptions of what worked
    observations: str = ""                # free-text synthesis
```

This is a Pydantic BaseModel used as `with_structured_output` schema for the extraction LLM call. Fields are optional — the LLM fills what it can infer. The `observations` field captures signals that don't fit the typed fields.

Rendering to text for the generation prompt is a pure function in `src/mcp_auditor/graph/prompts.py`.

## Tool ordering

A pure function on `list[ToolDefinition]` in `src/mcp_auditor/domain/models.py`:

```python
def order_tools_for_audit(tools: list[ToolDefinition]) -> list[ToolDefinition]:
```

Heuristic:
1. **Read-like tools first**: names starting with `get_`, `list_`, `read_`, `search_`, `find_`, `fetch_`, `show_`, `describe_`, `check_` sort before others.
2. **Tie-break by parameter count ascending**: fewer params = simpler to probe, reveals basic system characteristics faster.
3. **Stable within groups**: preserve discovery order for tools in the same bucket.

This runs after `filter_tools` in `discover_tools`, before the tool loop begins.

## Graph changes

### New field in `GraphState`

```python
class GraphState(TypedDict):
    # ... existing fields ...
    attack_context: AttackContext       # initialized empty, enriched after each tool
```

Initialized to `AttackContext()` (all defaults) in the initial state.

### New node: `extract_attack_context`

Factory: `make_extract_attack_context(llm: LLMPort)`.

Placed in the main graph between `finalize_tool_audit` and routing:

```
prepare_tool → audit_tool → finalize_tool_audit → extract_attack_context → route_tools
```

Input: the latest `ToolReport` (from `tool_reports[-1]`) + existing `attack_context`.
Output: updated `attack_context` + `token_usage`.

The node calls the LLM with an extraction prompt and the `AttackContext` structured output schema. It merges the new extraction with the existing context (accumulation, not replacement).

### Modified node: `generate_test_cases`

`make_generate_test_cases(llm)` stays the same factory signature. The node reads `attack_context` from state (it's available because `AuditToolState` needs a new field, or the subgraph input schema passes it through).

Add `attack_context` to `AuditToolInput` and `AuditToolState`:

```python
class AuditToolInput(TypedDict):
    current_tool: ToolDefinition
    test_budget: int
    attack_context: AttackContext    # new

class AuditToolState(TypedDict):
    # ... existing fields ...
    attack_context: AttackContext    # new, read-only within subgraph
```

`prepare_tool` already returns `current_tool` — the `attack_context` flows through from `GraphState` into the subgraph input naturally (LangGraph maps matching field names).

### Modified node: `discover_tools`

After filtering, apply `order_tools_for_audit` to the discovered tools.

### Dry-run graph

The dry-run graph also gets context-aware generation. It doesn't execute tools so there's no extraction, but `attack_context` still flows through the state (always empty). This avoids diverging the subgraph input schemas between normal and dry-run.

Note: the dry-run graph uses its own routing functions (`_route_to_tools_or_end`, `_route_to_next_tool_or_end`) and node name `generate_cases` (not `audit_tool`). No `extract_attack_context` node is added to the dry-run graph, only the state field.

## Prompts

### Extraction prompt

New function in `src/mcp_auditor/graph/prompts.py`:

```python
def build_context_extraction_prompt(
    tool_report: ToolReport,
    existing_context: AttackContext,
) -> str:
```

The prompt tells the LLM:
- Here is the tool definition and the test results (responses, errors, verdicts).
- Here is what we already know about this server (existing context, if non-empty).
- Extract any new intelligence: database engine, framework/language, internal paths/names, which attack patterns were effective, and any other observations.
- Merge with existing knowledge. Don't lose previous findings.

The prompt includes concrete examples (e.g., "if you see `sqlite3.OperationalError`, set `db_engine` to `sqlite`").

### Generation prompt addition

New function in `src/mcp_auditor/graph/prompts.py`:

```python
def format_attack_context(context: AttackContext) -> str:
```

Returns empty string if context is empty (first tool). Otherwise renders a section like:

```
Previous tool audits revealed the following about this server:
- Database engine: SQLite
- Framework: Flask (Python)
- Exposed internals: /opt/mcp-server/internal/users.db, table "users"
- Effective patterns: error-path probing with invalid IDs triggered verbose SQLite errors
- Observations: ...

Use this intelligence to craft more targeted payloads. For example, if the server uses SQLite, use SQLite-specific injection syntax rather than generic SQL.
```

`build_attack_generation_prompt` gets a new optional parameter:

```python
<!-- REVIEW: build_attack_generation_prompt goes from 3 to 4 parameters. Per CLAUDE.md "aim for ≤ 3" — acceptable here since the 4th is optional and the alternatives (a config object grouping tool+budget+categories+context, or currying) would add indirection without clarity. Revisit if more parameters accumulate. -->
def build_attack_generation_prompt(
    tool: ToolDefinition,
    budget: int,
    categories: list[AuditCategory],
    attack_context: AttackContext | None = None,   # new
) -> str:
```

If `attack_context` is provided and non-empty, the `format_attack_context` section is appended after the category guidance.

## Context merging

The extraction node receives the *existing* context and the LLM returns a *merged* context (not a delta). The extraction prompt instructs the LLM to incorporate previous findings. This avoids writing merge logic in code — the LLM handles deduplication naturally.

One concern: the LLM might drop previous findings. Mitigation: the prompt explicitly says "preserve all previous findings, add new ones." Since the context is small (a few fields), this is reliable.

## Files to modify

| File | Change |
|------|--------|
| `src/mcp_auditor/domain/models.py` | Add `AttackContext` model, add `order_tools_for_audit` function |
| `src/mcp_auditor/domain/__init__.py` | Export `AttackContext` and `order_tools_for_audit` |
| `src/mcp_auditor/graph/state.py` | Add `attack_context` field to `GraphState`, `AuditToolState`, `AuditToolInput` |
| `src/mcp_auditor/graph/prompts.py` | Add `build_context_extraction_prompt`, add `format_attack_context`, update `build_attack_generation_prompt` signature |
| `src/mcp_auditor/graph/nodes.py` | Add `make_extract_attack_context` factory, update `make_generate_test_cases` to pass context to prompt, update `make_discover_tools` to apply ordering |
| `src/mcp_auditor/graph/builder.py` | Wire `extract_attack_context` node between `finalize_tool_audit` and routing, update dry-run graph for state compatibility |
| `tests/fakes/llm.py` | No change needed — `FakeLLM` already handles any `BaseModel` |
| `tests/unit/test_nodes.py` | Tests for `extract_attack_context`, updated `generate_test_cases` |
| `tests/unit/fixtures/test_nodes_given.py` | Helpers: `an_attack_context()`, `a_tool_report_with_responses()` |
| `tests/unit/fixtures/test_nodes_then.py` | Assertions: `attack_context_has_db_engine()`, etc. |
| `tests/unit/test_graph.py` | Update `FakeLLM` response queues to include extraction responses, verify context flows |
| `tests/unit/fixtures/test_graph_given.py` | Update `a_fake_llm_for_single_tool_audit` and `a_fake_llm_for_multi_tool_audit` to include `AttackContext` responses, update `an_initial_state` |
| `tests/unit/test_prompts.py` | Test `build_context_extraction_prompt`, `format_attack_context`, generation prompt with/without context |
| `tests/unit/test_models.py` | Test `order_tools_for_audit` |

## What stays unchanged

- `src/mcp_auditor/domain/ports.py` — no new port needed, extraction uses `LLMPort`
- `src/mcp_auditor/domain/category_guidance.py` — category guidance is orthogonal to attack context
- `src/mcp_auditor/adapters/` — no adapter changes
- `evals/metrics.py`, `evals/judge_metrics.py` — eval metrics don't change
- Judge prompt — the judge evaluates results independently of context
- CLI — no new flags needed (cross-tool learning is always on)

## Edge cases

- **Single tool server**: no extraction happens (or extraction runs but produces empty context, which is fine — the next generation just doesn't get context). Actually, extraction still runs — it captures intelligence even if there's no next tool. This is harmless and keeps the flow uniform.
- **First tool**: `attack_context` is empty. `format_attack_context` returns empty string. Generation prompt is unchanged from today. No behavioral difference for the first tool.
- **LLM returns empty context**: all fields stay at defaults. The context section in the generation prompt is omitted. No impact.
- **Context grows with many tools**: not bounded initially. For typical servers (5-10 tools), the context stays small. If a server has 50+ tools, the observations field could grow. We'll address this if it becomes a real problem.

## Test scenarios

### Unit: `order_tools_for_audit`

| Input tools | Expected order |
|-------------|---------------|
| `[delete_user, get_user, list_items]` | `[get_user, list_items, delete_user]` |
| `[get_a(3 params), get_b(1 param)]` | `[get_b, get_a]` (tie-break by param count) |
| `[create_x, update_y]` | `[create_x, update_y]` (stable, both non-read) |
| `[search_logs, get_user]` | `[search_logs, get_user]` or `[get_user, search_logs]` (both read-like, stable) |
| `[]` | `[]` |

### Unit: `extract_attack_context` node

- Given a `ToolReport` with SQLite error traces and a fake LLM returning `AttackContext(db_engine="sqlite")`, the node returns updated `attack_context` with `db_engine="sqlite"`.
- Given an existing non-empty `attack_context`, the extraction prompt includes the existing context text.
- Token usage is accumulated.

### Unit: `generate_test_cases` with context

- Given a non-empty `attack_context`, the generation prompt includes the context section (assert on prompt content via a spy or by testing the prompt function directly).
- Given an empty `attack_context`, the generation prompt is identical to today.

### Unit: `build_context_extraction_prompt`

- Includes tool name and description.
- Includes response/error content from test cases.
- Includes existing context when non-empty.

### Unit: `format_attack_context`

- Empty context → empty string.
- Context with `db_engine="sqlite"` → string contains "sqlite".
- Context with multiple fields → all fields rendered.

### Integration: graph with two tools

- Two-tool audit with `FakeLLM`: response queue includes extraction response after first tool's judge responses. Verify that the second tool's generation prompt receives the context (testable via the fake LLM seeing the prompt).

Actually, with the current `FakeLLM` we can't inspect prompts. We test this at the graph level by verifying:
- The graph completes successfully with the right number of tool reports.
- Token usage reflects the extra extraction calls.
- The `attack_context` in the final state is non-empty.

### Eval: cross-tool scenario

Extend the existing honeypot eval. The existing `dummy_server.py` already has the perfect scenario:
- `get_user` leaks `sqlite3.OperationalError` on invalid IDs.
- `execute_query` is vulnerable to SQL injection.

With tool ordering, `get_user` will run before `execute_query` (read-like prefix). The extraction should capture `db_engine: sqlite` from `get_user`'s error responses. The generator for `execute_query` should then produce SQLite-specific payloads.

No new honeypot server needed. The eval improvement is measured indirectly via existing metrics (recall, precision). If cross-tool learning helps the generator produce better-targeted payloads for `execute_query`, we might see improved recall on injection for that tool.

A dedicated eval metric for cross-tool learning is not needed initially. If we want to measure it explicitly later, we can compare runs with and without context (by adding a `--no-cross-tool` flag), but that's out of scope for this plan.

## Verification

```bash
uv run pytest tests/unit/test_models.py       # order_tools_for_audit
uv run pytest tests/unit/test_prompts.py       # extraction + context formatting
uv run pytest tests/unit/test_nodes.py         # extract_attack_context node
uv run pytest tests/unit/test_graph.py         # end-to-end with context flow
uv run ruff check .                            # lint
uv run ruff format .                           # format
uv run pyright                                 # type check
uv run pytest                                  # all tests
```

## Implementation steps

### Step 1: Domain model, pure functions, and prompt functions

**Files**:
- `tests/unit/test_models.py` -- add `TestOrderToolsForAudit` class
- `tests/unit/test_prompts.py` -- add `TestContextExtractionPrompt`, `TestFormatAttackContext`, update `TestAttackGenerationPrompt`
- `src/mcp_auditor/domain/models.py` -- add `AttackContext` model and `order_tools_for_audit` function
- `src/mcp_auditor/domain/__init__.py` -- export `AttackContext` and `order_tools_for_audit`
- `src/mcp_auditor/graph/prompts.py` -- add `build_context_extraction_prompt`, `format_attack_context`, update `build_attack_generation_prompt` signature
- `src/mcp_auditor/graph/state.py` -- add `attack_context` field to `GraphState`, `AuditToolState`, `AuditToolInput`

**Do**:

1. Add `AttackContext` model to `src/mcp_auditor/domain/models.py` (place it after `ToolResponse`, before `AuditPayload`):
   ```python
   class AttackContext(BaseModel):
       """Accumulated intelligence from previous tool audits."""
       db_engine: str | None = None
       framework: str | None = None
       language: str | None = None
       exposed_internals: list[str] = []
       effective_payloads: list[str] = []
       observations: str = ""
   ```

2. Add `order_tools_for_audit` function to `src/mcp_auditor/domain/models.py` (place it after `filter_tools`). Heuristic: read-like prefixes (`get_`, `list_`, `read_`, `search_`, `find_`, `fetch_`, `show_`, `describe_`, `check_`) sort before others. Tie-break by parameter count ascending (count properties in `input_schema`). Use a stable sort to preserve discovery order within groups. Implementation: define `_READ_PREFIXES` as a tuple, write a sort key function `_audit_order_key(tool) -> tuple[int, int]` where the first element is 0 for read-like, 1 for others, and the second is the parameter count. Use `sorted(tools, key=_audit_order_key)` which is stable.

3. Export `AttackContext` and `order_tools_for_audit` from `src/mcp_auditor/domain/__init__.py`.

4. Add `attack_context: AttackContext` field to all three TypedDicts in `src/mcp_auditor/graph/state.py`. Import `AttackContext` from `mcp_auditor.domain.models`.

5. Add `format_attack_context(context: AttackContext) -> str` to `src/mcp_auditor/graph/prompts.py`. Returns empty string if all fields are at defaults (check `db_engine is None and framework is None and language is None and not exposed_internals and not effective_payloads and not observations`). Otherwise renders a structured section with header "Previous tool audits revealed the following about this server:" listing each non-empty field, followed by "Use this intelligence to craft more targeted payloads."

6. Add `build_context_extraction_prompt(tool_report: ToolReport, existing_context: AttackContext) -> str` to `src/mcp_auditor/graph/prompts.py`. The prompt instructs the LLM to extract intelligence from the tool report's test cases (iterate `tool_report.cases`, include each case's `payload.description`, `response`, `error`, and `eval_result.verdict`/`eval_result.justification` if present). Include the tool's name and description. If existing context is non-empty (use `format_attack_context`), include it under "What we already know:". Tell the LLM to preserve all previous findings and add new ones. Include concrete examples like "if you see sqlite3.OperationalError, set db_engine to sqlite".

7. Update `build_attack_generation_prompt` signature to accept `attack_context: AttackContext | None = None` as a 4th optional parameter. If provided and non-empty, append the `format_attack_context` output after the category guidance section (before the final "Always send arguments..." paragraph).

**Test** (write tests first, confirm they fail, then implement):

- `TestOrderToolsForAudit` in `tests/unit/test_models.py`:
  - `test_read_like_tools_sort_before_others`: `[delete_user, get_user, list_items]` -> `[get_user, list_items, delete_user]`
  - `test_ties_broken_by_parameter_count`: two `get_` tools with 3 and 1 params respectively -> 1-param tool first. Create tools with `input_schema={"type": "object", "properties": {"a": {}, "b": {}, "c": {}}}` for 3 params.
  - `test_stable_within_same_group`: `[create_x, update_y]` -> `[create_x, update_y]` (preserved)
  - `test_empty_list`: `[]` -> `[]`
  - `test_all_read_prefixes_recognized`: one tool for each prefix (`get_`, `list_`, `read_`, `search_`, `find_`, `fetch_`, `show_`, `describe_`, `check_`) plus one non-read tool -> all read-like tools appear before the non-read tool

- `TestFormatAttackContext` in `tests/unit/test_prompts.py`:
  - `test_empty_context_returns_empty_string`: `AttackContext()` -> `""`
  - `test_context_with_db_engine`: `AttackContext(db_engine="sqlite")` -> string contains "sqlite"
  - `test_context_with_multiple_fields`: context with `db_engine`, `framework`, `exposed_internals` -> all rendered

- `TestContextExtractionPrompt` in `tests/unit/test_prompts.py`:
  - `test_includes_tool_name`: prompt contains the tool name from the report
  - `test_includes_response_content`: prompt contains response text from test cases
  - `test_includes_existing_context_when_non_empty`: when existing context has `db_engine="sqlite"`, prompt contains "sqlite"
  - `test_omits_existing_context_when_empty`: when existing context is default `AttackContext()`, prompt does not contain "What we already know" (or equivalent header)

- Update `TestAttackGenerationPrompt` in `tests/unit/test_prompts.py`:
  - `test_includes_attack_context_when_provided`: pass `attack_context=AttackContext(db_engine="sqlite")`, assert "sqlite" in prompt
  - `test_omits_attack_context_when_none`: pass no `attack_context`, assert "Previous tool audits" not in prompt
  - `test_omits_attack_context_when_empty`: pass `attack_context=AttackContext()`, assert "Previous tool audits" not in prompt

**Verify**:
```bash
uv run pytest tests/unit/test_models.py tests/unit/test_prompts.py -x
uv run ruff check src/mcp_auditor/domain/models.py src/mcp_auditor/domain/__init__.py src/mcp_auditor/graph/prompts.py src/mcp_auditor/graph/state.py
uv run ruff format src/mcp_auditor/domain/models.py src/mcp_auditor/domain/__init__.py src/mcp_auditor/graph/prompts.py src/mcp_auditor/graph/state.py
uv run pyright src/mcp_auditor/domain/models.py src/mcp_auditor/graph/prompts.py src/mcp_auditor/graph/state.py
```

### Step 2: Graph nodes, builder wiring, and graph-level tests

**Files**:
- `tests/unit/fixtures/test_nodes_given.py` -- add `an_attack_context()`, `a_tool_report()`
- `tests/unit/fixtures/test_nodes_then.py` -- add `attack_context_has_db_engine()`
- `tests/unit/test_nodes.py` -- add `TestExtractAttackContext`, update `TestGenerateTestCases`, update `TestDiscoverTools`
- `tests/unit/fixtures/test_graph_given.py` -- update FakeLLM response queues and `an_initial_state`
- `tests/unit/fixtures/test_graph_then.py` -- add `attack_context_is_non_empty()`
- `tests/unit/test_graph.py` -- update existing tests for new LLM call count, add context flow verification
- `src/mcp_auditor/graph/nodes.py` -- add `make_extract_attack_context`, update `make_generate_test_cases`, update `make_discover_tools`
- `src/mcp_auditor/graph/builder.py` -- wire `extract_attack_context` node, update dry-run graph state

**Do**:

1. Add `make_extract_attack_context(llm: LLMPort)` factory to `src/mcp_auditor/graph/nodes.py`. The inner function reads `tool_reports[-1]` and `attack_context` from state, calls `build_context_extraction_prompt(tool_report, existing_context)`, then `llm.generate_structured(prompt, AttackContext)`. Returns `{"attack_context": new_context, "token_usage": [usage]}`. Import `build_context_extraction_prompt` and `AttackContext`.

2. Update `make_generate_test_cases` in `src/mcp_auditor/graph/nodes.py`: read `attack_context` from state (with `state.get("attack_context")` for backward compatibility), pass it to `build_attack_generation_prompt` as the 4th argument.

3. Update `make_discover_tools` in `src/mcp_auditor/graph/nodes.py`: after `filter_tools`, apply `order_tools_for_audit` to the result. Import `order_tools_for_audit`.

4. Wire the new node in `src/mcp_auditor/graph/builder.py`:
   - Import `make_extract_attack_context` from nodes.
   - In `build_graph`: add node `"extract_attack_context"` using `make_extract_attack_context(llm)`. Change the edge from `finalize_tool_audit` -> (conditional `route_tools`) to: `finalize_tool_audit` -> `extract_attack_context` -> (conditional `route_tools`). Specifically: `builder.add_edge("finalize_tool_audit", "extract_attack_context")` and `builder.add_conditional_edges("extract_attack_context", route_tools)`. Remove the old `builder.add_conditional_edges("finalize_tool_audit", route_tools)`.
   - The dry-run graph (`build_dry_run_graph` / `_build_generate_only_subgraph`) needs no `extract_attack_context` node. The `attack_context` field flows through the state naturally (LangGraph handles missing fields with defaults). No changes needed to dry-run routing or node wiring -- only the `AuditToolInput`/`AuditToolState` TypedDict changes from Step 1 ensure schema compatibility.

5. Update test fixtures in `tests/unit/fixtures/test_nodes_given.py`:
   - Add `an_attack_context(db_engine=None, framework=None, ...) -> AttackContext` helper.
   - Add `a_tool_report(tool_name="test_tool", num_cases=1) -> ToolReport` helper that creates a report with test cases that have responses/errors.

6. Update test assertions in `tests/unit/fixtures/test_nodes_then.py`:
   - Add `attack_context_has_db_engine(result, expected)` that asserts `result["attack_context"].db_engine == expected`.

7. Update `tests/unit/fixtures/test_graph_given.py`:
   - Update `a_fake_llm_for_single_tool_audit`: after the judge eval results, append an `AttackContext()` response (extraction response). So the response queue becomes: `[batch, *eval_results, AttackContext()]`. Import `AttackContext`.
   - Update `a_fake_llm_for_multi_tool_audit`: after each tool's eval results, append an `AttackContext()` response. So for each `(tool_name, num_cases)`: `[batch, *eval_results, AttackContext()]`.
   - Update `an_initial_state`: add `"attack_context": AttackContext()` to the returned dict. Import `AttackContext`.

8. Update `tests/unit/fixtures/test_graph_then.py`:
   - Add `attack_context_is_non_empty(result)` that asserts the final `attack_context` has at least one non-default field.

**Test** (write tests first, confirm they fail, then implement):

- `TestExtractAttackContext` in `tests/unit/test_nodes.py`:
  - `test_extracts_context_from_tool_report`: Create a `ToolReport` via `given.a_tool_report()`. Create a FakeLLM returning `AttackContext(db_engine="sqlite")`. Build the node with `make_extract_attack_context(llm)`. Invoke with state containing `tool_reports=[report]` and `attack_context=AttackContext()`. Assert `then.attack_context_has_db_engine(result, "sqlite")`.
  - `test_accumulates_token_usage`: Same setup. Assert `result["token_usage"]` has one `TokenUsage` entry.

- Update `TestGenerateTestCases` in `tests/unit/test_nodes.py`:
  - `test_passes_attack_context_to_prompt`: This is better tested via the prompt tests in step 1. The node test just needs to confirm the node still works when `attack_context` is present in state. Update the existing `test_produces_pending_cases` to include `"attack_context": AttackContext()` in the state dict passed to the node.

- Update `TestDiscoverTools` in `tests/unit/test_nodes.py`:
  - `test_orders_tools_for_audit`: Create tools `[delete_user, get_user]`, invoke `make_discover_tools(client)`. Assert the result has `get_user` before `delete_user` (via `then.discovered_tools_are`).

- Update `tests/unit/test_graph.py`:
  - All existing tests should pass with the updated FakeLLM response queues (the extra `AttackContext()` response per tool accounts for the new extraction call).
  - `test_token_usage_accumulated`: Update expected token counts. Previously 3 LLM calls for 1 tool with 2 cases (1 generate + 2 judge = 3). Now 4 LLM calls (1 generate + 2 judge + 1 extract = 4). So `input_tokens == 40` (4 * 10) and `output_tokens == 20` (4 * 5).
  - Add `test_attack_context_populated_after_audit`: Single-tool audit. Use `a_fake_llm_for_single_tool_audit` but with a non-empty `AttackContext(db_engine="sqlite")` as the extraction response (override the default). Assert `then.attack_context_is_non_empty(result)` or assert `result["attack_context"].db_engine == "sqlite"`.

**Verify**:
```bash
uv run pytest tests/unit/test_nodes.py tests/unit/test_graph.py -x
uv run ruff check .
uv run ruff format .
uv run pyright
uv run pytest
```
