# Report a step the model provider refuses, and fail `--ci` on an incomplete audit

## Context

During a honeypot baseline recording on 2026-09-26, OpenAI refused one `gpt-6-luna` call before it reached the model: `400 invalid_prompt`, "your prompt was flagged as potentially violating our usage policy", on the chain planning of the chain honeypot. The exception is not caught, so the whole audit stopped and everything it had tested was lost. A measurement that followed (15 full audits, 300 targeted replays, about 1,000 calls in all) saw no other refusal, so the event is rare, but an auditor sends offensive content by nature and every moderated provider can refuse a step: Alibaba Cloud Model Studio refused 12 attack-chain calls in the probe of ADR 019.

Two things are wrong today:

1. **A refusal crashes the audit.** The report of everything that ran before is lost.
2. **An incomplete audit can pass CI.** `--ci` exits 1 only on findings at or above the severity threshold. A tool left with a coverage gap after the completion of missing categories is reported, but the exit code is 0, so a green CI can mean "partly untested".

Catching the refusal must not hide it. The auditor did not do part of its job, and the report and the exit code have to say so as loudly as a finding.

## Approach

1. **A domain exception for a provider refusal.** `ProviderRefusal` in `domain/ports.py`, raised by the LLM adapter when a provider refuses a request or an answer on policy grounds. Every other error keeps propagating as today.
2. **The adapter recognizes the refusals of the four providers.** OpenAI and Alibaba (observed), Anthropic and Google, both a candidate stopped for safety and a prompt blocked before any candidate (from the libraries, verified against the locked versions).
3. **Every graph node that calls the model catches `ProviderRefusal`** and records a `RefusedStep` (tool, step, provider message), then carries on with what it has: a case stays unjudged, a chain ends without a verdict, a tool's generation keeps the cases it already had, the attack context stays as it was.
4. **The report carries the refused steps.** `AuditReport.refused_steps`, rendered in the Markdown summary and under each tool, in the JSON report, and as console warnings. A case or chain left unjudged is rendered as such, never silently dropped.
5. **An incomplete audit fails `--ci` with its own exit code, 3.** Incomplete means at least one refused step or one coverage gap. Findings at or above the threshold keep exit code 1, which takes precedence. Code 2 is left to Click, which uses it for usage errors.

## Domain

### `src/mcp_auditor/domain/ports.py`

```python
class ProviderRefusal(Exception):
    """The provider refused the request or its answer on policy grounds, before or instead of a model answer."""

    def __init__(self, provider_message: str, usage: TokenUsage):
        super().__init__(provider_message)
        self.provider_message = provider_message
        self.usage = usage
```

Not a subclass of `ValueError`, so no existing `except ValueError` (CLI, probe) absorbs it by accident. It carries the token usage of every attempt of the call, as `UnparseableOutput` does: a model-level refusal is billed, and the report's usage and the evals' cost figures must keep counting it. A refusal raised from an exception carries the usage accumulated by earlier attempts of the same call (zero when the first attempt is refused). Each node that records a `RefusedStep` also returns that usage in `token_usage`.

### `src/mcp_auditor/domain/models.py`

```python
class AuditStep(StrEnum):
    TEST_GENERATION = "test_generation"
    JUDGMENT = "judgment"
    CONTEXT_EXTRACTION = "context_extraction"
    CHAIN_PLANNING = "chain_planning"
    CHAIN_STEP_OBSERVATION = "chain_step_observation"
    CHAIN_STEP_PLANNING = "chain_step_planning"
    CHAIN_JUDGMENT = "chain_judgment"


class RefusedStep(BaseModel):
    tool_name: str
    step: AuditStep
    provider_message: str
```

`AuditReport` gains `refused_steps: list[RefusedStep] = []` and a property:

```python
@property
def is_complete(self) -> bool:
    return not self.refused_steps and all(tr.coverage_gap is None for tr in self.tool_reports)
```

A property is not serialized by Pydantic, which matches how `findings` works today. The JSON report carries `refused_steps` and the existing `coverage_gap` entries, from which a reader derives completeness.

## Adapter: `src/mcp_auditor/adapters/llm.py`

`generate_structured` translates a refusal into `ProviderRefusal`, in two places:

- **An exception from `ainvoke`**: walk the exception and its `__cause__` chain. `langchain-openai` re-raises every 400 as `OpenAIInvalidRequestError`, a subclass of `openai.BadRequestError` whose `code` attribute the SDK fills from the error body. OpenAI: `code == "invalid_prompt"`. Alibaba (through the same SDK): `code == "data_inspection_failed"`, the body recorded in `evals/probe_runs/2026-09-25_adr-019.json` (its message holds `DataInspectionFailed`). Both are the ones this repository observed (probe of ADR 019, recording of 2026-09-26). Match on the `code` first, and on the message text as a fallback for either provider (`invalid_prompt` wording, `DataInspectionFailed`), since a provider can change one without the other.
- **A response that carries a refusal instead of an answer**, read from the raw `AIMessage` in `_unpack_raw_response`, before the truncation check. Anthropic: `response_metadata["stop_reason"] == "refusal"` (`langchain-anthropic` copies the API's `stop_reason` there). Google: a candidate whose `response_metadata["finish_reason"]` is among the safety values such as `SAFETY` and `PROHIBITED_CONTENT` (`langchain-google-genai` 4.2.1 writes the enum name there). OpenAI: a model-level refusal under structured outputs, which `langchain-openai` puts in `additional_kwargs["refusal"]` (Chat Completions) or in a `refusal` content block (Responses API, the path `gpt-6-luna` takes). The adapter passes OpenAI and Alibaba a dict schema, so the parser is `JsonOutputParser`, not the one that raises `OpenAIRefusalError`: a refusal fails it with `OutputParserException`, which `include_raw=True` swallows into `parsing_error`, so today it would be retried three times and end as `UnparseableOutput`. The field names and values above were checked against the locked versions in due diligence, and the matching is written from them, not guessed.
- **Google's prompt block**: under `include_raw=True`, langchain-core 1.6.4 merges a single generation's `llm_output` into `response_metadata`, so a prompt blocked before any candidate shows as `response_metadata["prompt_feedback"]["block_reason"]` set (a `BlockedReason` enum), with an empty message. `_refusal_from_metadata` reads it next to the candidate's `finish_reason`. Its value comes from a simulation, since no Google block was observed here.

The provider's own message becomes `provider_message`. A refusal is not retried by the adapter: the same prompt would meet the same policy, and a retry would only add cost and delay. The recognition lives in one private function per form (`_refusal_from_error`, `_refusal_from_metadata`), each with a comment naming the provider and the source of the marker.

## Graph

### State (`src/mcp_auditor/graph/state.py`)

`refused_steps: Annotated[list[RefusedStep], operator.add]` in `GraphState`, `AuditToolState` and `ChainAuditState`, like `token_usage`, so refusals recorded in the two subgraphs reach the parent state.

### Nodes (`graph/nodes.py`, `graph/chain_nodes.py`)

Each node that calls the model catches `ProviderRefusal` and returns a `RefusedStep` in `refused_steps`, with the tool name and the step:

- `generate_test_cases` (`TEST_GENERATION`): a refusal on the first call leaves the tool with no case and a coverage gap of 0 received cases. A refusal on the retry keeps the first batch with its gap, a refusal on the completion keeps the retried batch with its gap. The node runs in both the audit subgraph and the dry-run subgraph (`_build_generate_only_subgraph`), and `AuditToolState` is shared by both. Either way the refused step is recorded, and the tool's other steps go on.
- `judge_response` (`JUDGMENT`): the case is appended to `judged_cases` with `eval_result=None`.
- `extract_attack_context` (`CONTEXT_EXTRACTION`): the attack context stays as it was.
- `plan_chains` (`CHAIN_PLANNING`): no chain is planned for that tool.
- `observe_step` (`CHAIN_STEP_OBSERVATION`) and `plan_step` (`CHAIN_STEP_PLANNING`): the chain stops and goes to `judge_chain` with the steps it has, since each executed step is evidence worth judging. The routing reads a state flag set by the node, as `blocked_step_reason` already does for a blocked step: a `chain_step_refused: bool` key in `ChainAuditState`, reset to `False` by `prepare_chain` and `judge_chain`. `route_after_observe` checks it first (on a refused observation `current_observation` is stale or `None`, and reading `obs.should_continue` would fail). `plan_step` has a plain edge to `execute_step` today (`graph/builder.py`), so it gets a new conditional edge, `route_after_plan_step`, to `execute_step` or `judge_chain`.
- `judge_chain` (`CHAIN_JUDGMENT`): the chain is completed with `eval_result=None`.

`generate_report` passes `state.get("refused_steps", [])` to `AuditReport`, like `token_usage`.

`graph/builder.py`: the new conditional edge after `plan_step` (above). `refused_steps` stays out of `AuditToolInput` and `ChainAuditInput`, so each subgraph starts empty and the parent's `operator.add` does not count a refusal twice.

The catch is written once, as a small helper in the graph that runs a model call and returns either the result or a `RefusedStep`, so the nine call sites do not repeat the same `try`/`except`. Its exact shape is left to the implementation, within the 20-line and 3-argument rules.

## Rendering and console

- `domain/rendering.py`:
  - Summary: a line `**Refused by the model provider**: N steps` when N > 0, and `**Audit complete**: no` when `report.is_complete` is false, placed before the findings so an incomplete report says so before anything else.
  - Tool section: one line per refused step of that tool, `**Refused by the model provider**: <step>, "<provider message>"`, next to the existing coverage gap line.
  - A case with no `eval_result` and no `blocked_reason` is rendered `### NOT JUDGED -- <category>`, with its payload and "the model provider refused the judgment". A chain with no `eval_result` gets a `**Verdict**: not judged` line. Today such a case is skipped silently.
- `console.py`: `print_summary` prints a warning per refused step, next to the coverage gap warnings, and one final warning when the audit is incomplete.
- JSON: `refused_steps` is serialized with the report (Pydantic default).
- `audit.py`, `_show_payloads` (dry run): prints a warning per refused step from `result.get("refused_steps", [])`, next to its coverage gap warnings. Without it a dry run shows a refused tool as an empty batch.
- `stream_handler.py`: a `judge_response` update whose case has no `eval_result` advances the progress bar without a result (as `advance_blocked` does), so the bar of a tool with a refused judgment still reaches its total.

## CLI: `src/mcp_auditor/cli.py`

After the findings check, in `--ci` mode only. The decision is a pure function, so the CLI tests reach it without running an audit (no existing CLI test fakes a report: `_deliver` is private and `test_cli.py` only drives Click on `--help` and a refused launch):

```python
def ci_exit_code(report: AuditReport, ci: CIOptions) -> int:
    if not ci.enabled:
        return 0
    if report.has_findings_at_or_above(ci.severity_threshold):
        return 1
    return 0 if report.is_complete else 3
```

`_deliver` raises `SystemExit(code)` when it is not 0. The `--ci` option help, `"CI mode: plain output, exit 1."`, says exit 1 on findings, 3 on an incomplete audit.

Outside `--ci`, the exit code does not change: the warnings and the report carry the information.

## Living docs

- `README.md`: the `--ci` row and paragraph say it also exits 3 when the audit is incomplete (a step refused by the model provider, or a tool left with a coverage gap), and that findings take precedence with exit 1. One sentence where coverage gaps are described, on refused steps being reported the same way.
- `CHANGELOG.md`, `[Unreleased]`:
  - *Changed*, **Breaking.**: `--ci` exits 3 on an incomplete audit, including a coverage gap that used to pass.
  - *Changed* (or *Fixed*): a step the model provider refuses no longer stops the audit. It is reported as refused, in the console, the Markdown report and the JSON report (`refused_steps`), and a case or chain it leaves unjudged is shown as not judged.
- `CLAUDE.md`, `CONTRIBUTING.md`: nothing, no command or prerequisite changes.

## The eval instrument (separate step and commit)

A refused judgment on the only case of a honeypot cell makes the cell lose its observation, and the gate would read that like a miss with nothing saying a refusal caused it. The eval output records the refused steps of each run, as it already records the blocked payloads:

- `evals/metrics.py`: `RunDetail` gains `refused_steps: list[str] = []`, filled in `build_run_detail` from `audit_report.refused_steps`, one line per step (`"<tool>: <step>, <provider message>"`), as `blocked_reasons` does.
- `evals/eval_display.py`: prints them per run next to the blocked payloads.
- `evals/run_cve_benchmark.py`: prints them next to its `blocked_reasons` lines.
- `evals/run_probe.py`, `observe`: an explicit `except ProviderRefusal` before the generic `except Exception`, recorded as `CallOutcome.PARSE_FAILURE` with the refusal's usage and its provider message in `error`. A model-level refusal ended as `UnparseableOutput`, a `PARSE_FAILURE`, before this change, so its count does not move. A refusal returned as a 400 (OpenAI's `invalid_prompt`, Alibaba's `DataInspectionFailed`) was an `ERROR` and becomes a `PARSE_FAILURE`, which on a `TestCaseBatch` `_is_refusal` counts as a refusal. That move is deliberate: the method note tells a reader to rerun the probe on an error, and a policy refusal is not transient. The labeling log entry states it, with the ADR 019 run as the case it would have changed (Qwen's 12 rejections, errors then, refusals and parse failures now). `evals/probe_method.md` says the same in its bars. Test: an observation of a call raising `ProviderRefusal` is a `PARSE_FAILURE` carrying the usage and the message.

No scoring, label, gate, bar or baseline logic changes: this only makes a refusal visible where a reader of the gate looks. It is an instrument change, so it goes in its own commit, after the product commits, with an entry in `docs/labeling-log.md` saying what changed in the output and that no metric moves. Its justification stands alone (a refusal must not read as a miss) and borrows nothing from the product change. An eval run between the product commits and this one is optional: no baseline is committed, so no gate is at stake, and it would only confirm that an audit now completes.

## What stays unchanged

- The prompts, the models, the providers' settings, the output cap, the timeouts.
- Errors other than a policy refusal: they propagate as today.
- `--ci` exit 1 on findings, and the severity threshold.
- The destructive-payload guard and `blocked_reason`.
- The evals' code. `aggregate_verdicts` already skips a case or chain with no `eval_result`, so a refused judgment leaves its cell with one observation fewer, and a run with a refusal completes instead of failing.
- The eval instrument, in this plan's product commits. Its change is a separate step and commit, see *The eval instrument* below.
- The untracked exploratory baseline in `evals/baselines/` is not part of this change. It was recorded at `d8d109e`, is stale once this lands, and is deleted by hand before the two baseline recordings are made again.

## Edge cases

- **Refusal on the first generation call**: the tool has no case, a coverage gap of 0 received, one refused step. Chains, if enabled, are still planned from no case, as today for an empty batch.
- **Several refusals on one tool**: one `RefusedStep` each.
- **A refused judgment on a case that would have been a finding**: the finding is not reported, the case is shown as not judged, and `--ci` exits 3. The audit does not pass.
- **Refusal and findings in the same audit, `--ci`**: exit 1.
- **`--resume` across a refusal**: the refused step is in the checkpointed state like any other node output, so a resumed audit keeps it.
- **An unrecognized refusal form** (a provider changes its error): it propagates as today. The matching functions are the one place to extend.

## Test scenarios

Test-first, with the existing fakes. `FakeLLM` gains a way to raise `ProviderRefusal` on a given schema or call, if it has none.

- Adapter (`tests/unit/test_llm_adapter.py`): an exception chain holding an OpenAI `BadRequestError` with code `invalid_prompt` raises `ProviderRefusal` carrying the message. An Alibaba error with `code == "data_inspection_failed"` does too, and so does an error whose code is missing but whose message holds `DataInspectionFailed` or OpenAI's policy wording. A Google response whose metadata holds a `prompt_feedback.block_reason` raises `ProviderRefusal`. A refused call's `ProviderRefusal` carries the usage of its attempts. A response whose metadata carries Anthropic's `refusal` stop reason, and one carrying Google's block, raise `ProviderRefusal`. Another `BadRequestError` still raises as before. A truncated answer is still retried, not taken for a refusal.
- Graph (the existing node and graph tests, given/then): a refused judgment leaves the case unjudged and records a `JUDGMENT` refused step, and the audit goes on to the next case. A refused chain planning records `CHAIN_PLANNING` and the tool report has no chain. A refused step observation ends the chain, which is still judged. A refused first generation leaves the tool with no case, a gap and a refused step, and the next tool is audited. A refused context extraction keeps the previous context.
- Report: `is_complete` is false with a refused step, false with a coverage gap, true otherwise. The Markdown summary shows the refused count and "Audit complete: no". A case with no verdict and no block is rendered NOT JUDGED.
- CLI (`ci_exit_code`, a report built by hand): 3 on an incomplete report without findings, 1 on findings whether complete or not, 0 on a complete report without findings, 0 on an incomplete report without `--ci`.
- Chain routing: a refused step planning ends the chain in `judge_chain` rather than `execute_step`. A chain after a refused one starts with the flag reset.
- Dry run: a refused generation shows a warning.

## Verification

```bash
uv run pytest tests/unit
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

## After this plan

By hand: delete the untracked `evals/baselines/honeypot_e2e.json`, then record the two honeypot baselines again at one commit, as ADR 020 sets.

## Commit messages

Each commit says what the user now sees. The commit that changes the `--ci` exit code says it is breaking for a CI that passed with a coverage gap. No plan, step or phase named.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites, on 2026-09-26, against the locked versions in `uv.lock` (read from the installed sources and, where noted, a simulated response). Later passes read it. No pass may treat a line here as a reason to skip a verification: it records what was concluded once, not what is true now. A human who edits one of these facts by hand deletes its line rather than updating it.

- SETTLED: `langchain-openai` 1.6.6 re-raises every `openai.BadRequestError` as `OpenAIInvalidRequestError(openai.BadRequestError, ...)` with `body=e.body`, so `code` is filled from the error body (verified in `langchain_openai/chat_models/base.py`, `openai/_exceptions.py` 3.19.2)
- SETTLED: `code == "data_inspection_failed"` for Alibaba (verified in `evals/probe_runs/2026-09-25_adr-019.json`, message `InternalError.Algo.DataInspectionFailed`)
- SETTLED: `code == "invalid_prompt"` for OpenAI's policy flag (verified in the error body logged by the recording of 2026-09-26: `'code': 'invalid_prompt'`)
- SETTLED: `response_metadata["stop_reason"] == "refusal"` for Anthropic (verified: `anthropic` 0.84.0 `StopReason`, and `langchain-core` 1.6.4 merges `llm_output` into `response_metadata`, by simulation)
- SETTLED: `response_metadata["finish_reason"]` holds the enum name, e.g. `"SAFETY"`, `"PROHIBITED_CONTENT"`, for a Google candidate (verified in `langchain-google-genai` 4.2.1 and by simulation)
- SETTLED: `additional_kwargs["refusal"]` on Chat Completions (Alibaba path, `chat.completions.parse`), and a content block `{"type": "refusal", "refusal": ...}` in `AIMessage.content` on the Responses API (verified in `langchain-openai` 1.6.6 and by simulation)
- SETTLED: with the dict schema the adapter passes, the parser is `JsonOutputParser`, and a refusal ends in `parsing_error` as `OutputParserException`, not `OpenAIRefusalError` (corrected, verified by simulation)
- SETTLED: Google's prompt block reaches `response_metadata["prompt_feedback"]["block_reason"]` under `include_raw=True` (corrected, verified by simulation)
- SETTLED: Click uses exit code 2 for usage errors (`UsageError.exit_code = 2`, `click` 8.3.1)

## Implementation steps

Verification commands for every step: `uv run pytest tests/unit` (and `uv run pytest` at the end of the step), `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`. All must pass, with no new pyright error in strict mode. Tests are written first and run red before the production code.

### Step 1: Domain types and refusal recognition in the LLM adapter

- **Files**: `tests/unit/test_llm_adapter.py`, `tests/unit/test_models.py` (plus `tests/unit/support/test_models_given.py` if a report builder is worth extracting), `src/mcp_auditor/domain/ports.py`, `src/mcp_auditor/domain/models.py`, `src/mcp_auditor/adapters/llm.py`
- **Do**:
  1. Tests first (see Test below), using the existing fake chat-model setup of `test_llm_adapter.py`.
  2. `domain/ports.py`: `ProviderRefusal(Exception)` exactly as in *Domain*, carrying `provider_message` and `usage: TokenUsage`. Not a `ValueError` subclass.
  3. `domain/models.py`: `AuditStep` (StrEnum, the seven values of *Domain*), `RefusedStep(tool_name, step, provider_message)`, `AuditReport.refused_steps: list[RefusedStep] = []` and the `is_complete` property.
  4. `adapters/llm.py`, in `generate_structured`:
     - Wrap `structured.ainvoke(prompt)`: on any exception, `_refusal_from_error(exception)` walks the exception and its `__cause__` chain, and returns the provider message when an `openai.BadRequestError` has `code` in `{"invalid_prompt", "data_inspection_failed"}`, or, as a fallback, when the message text holds `invalid_prompt`/OpenAI's "flagged as potentially violating our usage policy" wording or `DataInspectionFailed`. If found, raise `ProviderRefusal(message, accumulated_usage)` from the exception; otherwise re-raise unchanged.
     - In `_unpack_raw_response` (or right after it, before the truncation check), `_refusal_from_metadata(raw_message)` returns a provider message when: `response_metadata["stop_reason"] == "refusal"` (Anthropic); `response_metadata["finish_reason"]` in the Google safety names (`SAFETY`, `PROHIBITED_CONTENT`, and the other safety values of the `FinishReason` enum in the locked `google-genai`: check `BLOCKLIST`, `SPII`, `IMAGE_SAFETY` and similar there); `response_metadata["prompt_feedback"]["block_reason"]` set (Google prompt block); `additional_kwargs["refusal"]` set (OpenAI Chat Completions, Alibaba); a content block `{"type": "refusal", ...}` in `AIMessage.content` (OpenAI Responses API). Raise `ProviderRefusal` with that message and the usage accumulated including this attempt. No retry.
     - One comment per recognized form naming the provider and the source of the marker. Keep functions under 20 lines, split the metadata check per provider if needed.
- **Test**:
  - Adapter: an `openai.BadRequestError` with `code="invalid_prompt"` (directly and wrapped as `__cause__` of another exception) raises `ProviderRefusal` carrying the message. `code="data_inspection_failed"` does too. A `BadRequestError` with no code but `DataInspectionFailed` in the message, and one with OpenAI's policy wording, raise `ProviderRefusal`. Another `BadRequestError` (e.g. `code="context_length_exceeded"`) propagates unchanged. Anthropic `stop_reason: "refusal"`, Google `finish_reason: "SAFETY"`, Google `prompt_feedback.block_reason` with an empty message, OpenAI `additional_kwargs["refusal"]`, and a Responses API refusal content block each raise `ProviderRefusal`. A refusal on the second attempt (first truncated) carries the usage of both attempts, a first-attempt error refusal carries zero usage. A truncated answer is still retried and still ends in `UnparseableOutput`, not taken for a refusal.
  - Models: `is_complete` false with a refused step, false with a coverage gap, true otherwise. `refused_steps` round-trips through `model_dump_json`/`model_validate_json`.
- **Verify**: the commands above, all green.

### Step 2: Tool-audit nodes record refusals and carry on

- **Files**: `tests/fakes/llm.py`, `tests/unit/test_nodes.py` (+ `support/test_nodes_given.py`, `support/test_nodes_then.py`), `tests/unit/test_generate_test_cases.py` (+ its given/then), `tests/unit/test_graph.py` (+ its given/then), `src/mcp_auditor/graph/state.py`, `src/mcp_auditor/graph/refusals.py` (new, or an equivalent home in `graph/`), `src/mcp_auditor/graph/nodes.py`
- **Do**:
  1. `FakeLLM`: a way to raise `ProviderRefusal` for a scripted response, e.g. accept a `ProviderRefusal` instance in the `responses` list and raise it when popped (usage `_FAKE_USAGE`). Keep the fake a real, deterministic implementation.
  2. Tests first (see Test).
  3. `graph/state.py`: `refused_steps: Annotated[list[RefusedStep], operator.add]` in `GraphState`, `AuditToolState` and `ChainAuditState`. Keep it out of `AuditToolInput` and `ChainAuditInput`.
  4. The shared helper in `graph/`: runs an `llm.generate_structured` call and returns either `(result, usage)` or a refusal outcome holding the `RefusedStep` (built from tool name and `AuditStep`) and the refusal's usage. Shape left to the implementer, within 20 lines and 3 arguments (a small Value Object naming "what is being asked, for which tool and step" is fine). Step 3 reuses it.
  5. `graph/nodes.py`:
     - `generate_test_cases` (`TEST_GENERATION`): refusal on the first call leaves no case and a coverage gap of 0 received cases. Refusal on the retry keeps the first batch with its gap. Refusal on the completion keeps the retried batch with its gap. Each records one `RefusedStep` and returns the refusal usage in `token_usage`. Valid for the audit subgraph and the dry-run subgraph.
     - `judge_response` (`JUDGMENT`): the case goes to `judged_cases` with `eval_result=None`, `current_case` reset, refused step recorded.
     - `extract_attack_context` (`CONTEXT_EXTRACTION`): the attack context unchanged, refused step recorded.
     - `generate_report`: `refused_steps=state.get("refused_steps", [])`.
- **Test**:
  - Node: a refused judgment leaves the case with no `eval_result` and records a `JUDGMENT` step for that tool, with the refusal's usage in `token_usage`. A refused context extraction keeps the previous context and records `CONTEXT_EXTRACTION`.
  - Generation: refused first call gives zero cases, a gap with 0 received, one `TEST_GENERATION` step. Refused retry keeps the first batch and its gap. Refused completion keeps the retried batch and its gap.
  - Graph: a refused judgment does not stop the audit, the next case is judged and the report carries the refused step. A refused first generation of the first tool leaves it with no case and a gap, and the second tool is audited. The dry-run graph with a refused generation completes and its final state carries the refused step (read by Step 4's dry-run warning).
- **Verify**: the commands above, all green.

### Step 3: Chain nodes record refusals, and a refused step ends the chain in its judgment

- **Files**: `tests/unit/test_chain_nodes.py` (+ `support/test_chain_nodes_given.py`, `support/test_chain_nodes_then.py`), `tests/unit/test_graph.py` (+ given/then) if a chain-level graph test is needed for routing, `src/mcp_auditor/graph/state.py`, `src/mcp_auditor/graph/chain_nodes.py`, `src/mcp_auditor/graph/builder.py`
- **Do**:
  1. Tests first (see Test).
  2. `state.py`: `chain_step_refused: bool` in `ChainAuditState`.
  3. `chain_nodes.py`, using the helper of Step 2:
     - `plan_chains` (`CHAIN_PLANNING`): no chain planned (`pending_chains: []`), refused step recorded.
     - `observe_step` (`CHAIN_STEP_OBSERVATION`) and `plan_step` (`CHAIN_STEP_PLANNING`): record the step and set `chain_step_refused: True`.
     - `judge_chain` (`CHAIN_JUDGMENT`): the chain is completed with `eval_result=None`, refused step recorded.
     - `prepare_chain` and `judge_chain` reset `chain_step_refused` to `False`.
     - `route_after_observe` checks `chain_step_refused` first and goes to `judge_chain`. New `route_after_plan_step`: `judge_chain` when the flag is set, `execute_step` otherwise.
  4. `builder.py`: replace the plain edge `plan_step -> execute_step` with a conditional edge on `route_after_plan_step`. Make sure `prepare_chain`/initial state give the flag a value before any router reads it.
- **Test**: a refused chain planning records `CHAIN_PLANNING` and routes to the end with no chain (tool report has no chain). A refused step observation routes to `judge_chain`, which judges the chain with the steps it has. A refused step planning routes to `judge_chain` rather than `execute_step`. A refused chain judgment completes the chain with `eval_result=None` and a `CHAIN_JUDGMENT` step. A chain after a refused one starts with the flag reset (`prepare_chain` returns `False`).
- **Verify**: the commands above, all green.

### Step 4: Report, console, dry run and progress show refused steps

- **Files**: `tests/unit/test_rendering.py` (+ `support/test_rendering_given.py`, `support/test_rendering_then.py`), `tests/unit/test_console_display.py` (+ `support/test_console_given.py`), `tests/unit/test_stream_handler.py`, `src/mcp_auditor/domain/rendering.py`, `src/mcp_auditor/console.py`, `src/mcp_auditor/audit.py`, `src/mcp_auditor/stream_handler.py`, `README.md`, `CHANGELOG.md`
- **Do**:
  1. Tests first (see Test).
  2. `rendering.py`: in the summary, before the findings, `**Refused by the model provider**: N steps` when N > 0 and `**Audit complete**: no` when `not report.is_complete`. In each tool section, one line per refused step of that tool, `**Refused by the model provider**: <step>, "<provider message>"`, next to the coverage gap line. A case with no `eval_result` and no `blocked_reason` renders `### NOT JUDGED -- <category>` with its payload and "the model provider refused the judgment". A chain with no `eval_result` gets `**Verdict**: not judged`.
  3. `console.py`: a display method printing one warning per refused step (reused by the summary and the dry run), called in `print_summary` next to the coverage gap warnings, plus one final warning when `not report.is_complete`.
  4. `audit.py` `_show_payloads`: print the refused-step warnings from `result.get("refused_steps", [])` next to its coverage gap warnings.
  5. `stream_handler.py`: a `judge_response` update whose case has no `eval_result` and no `blocked_reason` advances the progress bar without a result (as `advance_blocked` does). Add a progress method if needed.
  6. `README.md`: one sentence where coverage gaps are described, saying refused steps are reported the same way. `CHANGELOG.md` `[Unreleased]`, *Fixed*: a step the model provider refuses no longer stops the audit, it is reported as refused in the console, the Markdown report and the JSON report (`refused_steps`), and a case or chain it leaves unjudged is shown as not judged.
- **Test**: Markdown summary shows the refused count and "Audit complete: no" for a report with a refused step, and "Audit complete: no" for one with only a coverage gap, and neither line for a complete report. Tool section lists its refused step. A case with no verdict and no block renders NOT JUDGED. A chain with no verdict renders "not judged". JSON export carries `refused_steps` (in `test_export.py` if the JSON test lives there). Console summary prints a warning per refused step and the incomplete warning. The refused-step warning method is exercised as the dry run uses it. A `judge_response` update with an unjudged case advances the progress bar.
- **Verify**: the commands above, all green.

### Step 5: `--ci` exits 3 on an incomplete audit (breaking)

- **Files**: `tests/unit/test_cli.py`, `src/mcp_auditor/cli.py`, `README.md`, `CHANGELOG.md`
- **Do**:
  1. Tests first: `ci_exit_code` on reports built by hand.
  2. `cli.py`: public pure function `ci_exit_code(report, ci) -> int` as in *CLI*. `_deliver` raises `SystemExit(code)` when the code is not 0, replacing the current findings-only check. `--ci` help: CI mode, plain output, exit 1 on findings, 3 on an incomplete audit.
  3. `README.md`: the `--ci` row and paragraph say it also exits 3 when the audit is incomplete (a step refused by the model provider, or a tool left with a coverage gap), and that findings take precedence with exit 1. `CHANGELOG.md` `[Unreleased]`, *Changed*, **Breaking.**: `--ci` exits 3 on an incomplete audit, including a coverage gap that used to pass.
  4. The commit message says it is breaking for a CI that passed with a coverage gap.
- **Test**: 3 on an incomplete report (refused step) without findings, 3 on a report with only a coverage gap, 1 on findings at or above the threshold with a complete report and with an incomplete one, 0 on a complete report without findings, 0 on an incomplete report when CI is disabled.
- **Verify**: the commands above, all green.

### Step 6: Eval output shows refused steps (instrument change, own commit)

- **Files**: `tests/unit/test_eval_metrics.py` (+ `support/test_eval_metrics_given.py`), `tests/unit/test_run_probe.py`, `evals/metrics.py`, `evals/eval_display.py`, `evals/run_cve_benchmark.py`, `evals/run_probe.py`, `evals/probe_method.md`, `docs/labeling-log.md`
- **Do**:
  1. Tests first (see Test).
  2. `evals/metrics.py`: `RunDetail.refused_steps: list[str] = []`, filled in `build_run_detail` from `audit_report.refused_steps`, one line per step `"<tool>: <step>, <provider message>"`, beside `blocked_reasons`.
  3. `evals/eval_display.py` `print_run_result` and `evals/run_cve_benchmark.py`: print them next to the blocked-reason lines.
  4. `evals/run_probe.py` `observe`: `except ProviderRefusal` before the generic `except Exception`, giving `CallOutcome.PARSE_FAILURE`, the refusal's usage, and its provider message in `error`.
  5. `evals/probe_method.md`: say in its bars that a policy refusal returned as a 400 is now a parse failure (counted as a refusal on `TestCaseBatch`), not an error to rerun.
  6. `docs/labeling-log.md`: a dated entry in the style of the existing ones: what changed in the output, that no scoring, label, gate, bar or baseline logic changes and no metric moves, the probe reclassification (400 refusals from `ERROR` to `PARSE_FAILURE`) with the ADR 019 run as the case it would have changed (Qwen's 12 rejections), and a justification that stands alone (a refusal must not read as a miss).
- **Test**: `build_run_detail` on a report with a refused step lists it as `"<tool>: <step>, <message>"`, and an empty list without. `observe` on a call whose model raises `ProviderRefusal` returns `PARSE_FAILURE` with the refusal's usage and message.
- **Verify**: the commands above, all green. No `evals/baselines/` file is touched.
