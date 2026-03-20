# Plan: E2E Eval Case Export

**Date:** 2026-03-20

## Context

ADR 007 (Accepted) identifies a gap: the judge isolation eval (ADR 006) passes at F1 = 1.00 on curated cases, but e2e precision remains at 0.61. The curated cases don't represent real pipeline behavior — they're hand-crafted from what we imagine the generator produces.

The fix: the e2e eval exports every judged case with full context to `evals/judged_cases.jsonl`, allowing real false positives to be extracted and promoted into `judge_cases.json`.

The main implementation cost: `TestCase` context (description, arguments, response, error) is discarded after judging. It needs to flow through to `ToolReport` so the e2e eval runner can export it.

## Approach

`TestCase` already has an `eval_result: EvalResult | None` field that is never populated. The plan is to use it:

1. **Populate `TestCase.eval_result`** in the judge node — attach the verdict to the case instead of discarding it.
2. **Change `ToolReport` to store `list[TestCase]`** instead of `list[EvalResult]` — this preserves the full context (description, arguments, response, error, eval_result) through the pipeline.
3. **Update all consumers** of `ToolReport.results` to access eval results through `TestCase.eval_result`.
4. **Add JSONL export** to the e2e eval runner — write each judged case with ground truth comparison.

## Files to modify

### `src/mcp_auditor/domain/models.py`

Change `ToolReport.results: list[EvalResult]` → `ToolReport.cases: list[TestCase]`.

```python
class ToolReport(BaseModel):
    tool: ToolDefinition
    cases: list[TestCase]
```

### `src/mcp_auditor/graph/state.py`

Change `tool_results: list[EvalResult]` → `judged_cases: list[TestCase]` in both `GraphState` and `AuditToolState`.

```python
class GraphState(TypedDict):
    target: str
    discovered_tools: list[ToolDefinition]
    test_budget: int
    current_tool: ToolDefinition | None
    judged_cases: list[TestCase]
    tool_reports: Annotated[list[ToolReport], operator.add]
    audit_report: AuditReport | None

class AuditToolState(TypedDict):
    current_tool: ToolDefinition
    test_budget: int
    pending_cases: list[TestCase]
    current_case: TestCase | None
    judged_cases: list[TestCase]
```

Remove `EvalResult` import (no longer needed in state).

### `src/mcp_auditor/graph/nodes.py`

**`make_judge_response`**: attach eval_result to the TestCase, accumulate TestCases instead of EvalResults.

```python
def make_judge_response(llm: LLMPort):
    async def judge_response(state: dict[str, Any]) -> dict[str, Any]:
        case = state["current_case"]
        tool = state["current_tool"]
        prompt = build_judge_prompt(tool=tool, test_case=case)
        eval_result = await llm.generate_structured(prompt, EvalResult)
        judged = case.model_copy(update={"eval_result": eval_result})
        existing = list(state.get("judged_cases", []))
        existing.append(judged)
        return {"judged_cases": existing, "current_case": None}

    return judge_response
```

**`make_finalize_tool_audit`**: read from `judged_cases`, pass to `ToolReport(cases=...)`.

```python
def make_finalize_tool_audit():
    async def finalize_tool_audit(state: dict[str, Any]) -> dict[str, Any]:
        tool = state["current_tool"]
        cases = state["judged_cases"]
        report = ToolReport(tool=tool, cases=cases)
        return {"tool_reports": [report]}

    return finalize_tool_audit
```

**`make_generate_test_cases`**: rename `"tool_results"` → `"judged_cases"` in the returned state reset.

### `src/mcp_auditor/domain/rendering.py`

Update all functions that iterate `tool_report.results` to iterate `tool_report.cases` and access `case.eval_result`. Must filter out cases where `eval_result is None`:

- `_render_summary_section`: `sum(len(tr.results) ...)` → `sum(len(tr.cases) ...)`
- `_render_tool_section`: `for result in tool_report.results` → `for case in tool_report.cases`, skip if `case.eval_result is None`, then pass `case.eval_result` to `_render_result_section`
- `_collect_findings`: same pattern — filter on `case.eval_result is not None` before checking verdict

### `src/mcp_auditor/cli.py`

Two distinct consumers:

1. **`_handle_parent_event`** (finalize_tool_audit branch): `tool_report.results` → `tool_report.cases`, access `case.eval_result.verdict` for pass/fail counting. Must guard against `case.eval_result is None`.

2. **`_handle_subgraph_event`** (judge_response branch): reads `state_update.get("tool_results", [])` → `state_update.get("judged_cases", [])`. The last element is now a `TestCase`, not an `EvalResult` — access `case.eval_result` for `tool_name`, `category`, `severity`, and `verdict`. Must guard against `eval_result is None`.

### `src/mcp_auditor/console.py`

**`print_summary_table`**: `tool_report.results` → `tool_report.cases`, access `case.eval_result.verdict` for pass/fail counting. Must guard against `case.eval_result is None`.

No changes to `print_verdict` — it takes an `EvalResult` directly (the caller in `cli.py` extracts it from the `TestCase`).

### `evals/metrics.py`

- `aggregate_verdicts`: `for result in tool_report.results` → `for case in tool_report.cases`, use `case.eval_result`.
- `compute_distribution_coverage`: same.

### `evals/export.py` (new file)

Extract the JSONL export into a new module. `evals/run_evals.py` is already at ~310 lines; adding the export logic there would exceed the 300-line guideline.

### `evals/run_evals.py`

- `_build_verdict_detail`: same consumer update as above.
- Call `export_judged_cases` (imported from `evals.export`) after writing the eval report.

```python
# evals/export.py
def export_judged_cases(
    runs: list[tuple[int, AuditReport]],
    ground_truth: GroundTruth,
    report_path: Path,
) -> None:
    export_path = report_path.with_name("judged_cases.jsonl")
    with export_path.open("w") as f:
        for run_index, report in runs:
            for tool_report in report.tool_reports:
                for case in tool_report.cases:
                    result = case.eval_result
                    if result is None:
                        continue
                    gt_key = (result.tool_name, result.category)
                    expected = ground_truth.get(gt_key)
                    line = {
                        "run_index": run_index,
                        "tool_name": result.tool_name,
                        "tool_description": tool_report.tool.description,
                        "category": result.category.value,
                        "description": case.payload.description,
                        "arguments": case.payload.arguments,
                        "response": case.response,
                        "error": case.error,
                        "verdict": result.verdict.value,
                        "justification": result.justification,
                        "expected_verdict": expected.value if expected else None,
                        "correct": result.verdict == expected if expected else None,
                    }
                    f.write(json.dumps(line) + "\n")
```

This requires `_run_one_eval` to return the `AuditReport` (it already does). Changes to `run_evals()` and `main()`:

1. `run_evals()` must accumulate `(run_index, AuditReport)` pairs alongside `run_details` — currently `audit_report` is only passed to `_build_run_detail` and then discarded.
2. Either `run_evals()` returns the accumulated pairs (and `main()` calls `export_judged_cases`), or `run_evals()` accepts a `report_path` parameter. The simpler approach: `run_evals()` returns both `EvalReport` and the accumulated `list[tuple[int, AuditReport]]`, and `main()` calls `export_judged_cases` (from `evals.export`) after writing the eval report.
3. `main()` needs to pass `merged_ground_truth` to the export. This means either `run_evals()` also returns the merged ground truth, or the ground truth is reconstructed from `HONEYPOTS`. The simplest approach: return a dataclass/tuple containing `EvalReport`, `list[tuple[int, AuditReport]]`, and `GroundTruth` from `run_evals()`.

<!-- REVIEW: Decide the exact return type change for run_evals(). A named tuple or dataclass (e.g. EvalRunResult) would be cleaner than a raw 3-tuple, per the coding standards on extracting Value Objects when parameters accumulate. -->

### Unit tests

Update test fixtures that construct `ToolReport(results=[...])` → `ToolReport(cases=[...])` with TestCases that have `eval_result` populated:

- `tests/unit/test_console.py` — `_a_report_with_two_tools()` constructs `ToolReport(results=...)`
- `tests/unit/fixtures/test_rendering_given.py` — `a_tool_report()` constructs `ToolReport(results=...)`
- `tests/unit/fixtures/test_rendering_then.py` — `json_has_enum_strings()` accesses `tool_report["results"]` in JSON output; must change to `tool_report["cases"]` and navigate through `case["eval_result"]`
- `tests/unit/test_eval_metrics.py` — `_make_report()` constructs `ToolReport(results=...)`
- `tests/unit/fixtures/test_graph_then.py` — `report_has_results()` accesses `report.results`
- `tests/unit/test_nodes.py` — uses `"tool_results"` key in state dicts passed to nodes; must change to `"judged_cases"`. Test assertions change: `TestJudgeResponse` now asserts `judged_cases` contains a `TestCase` with `eval_result` populated; `TestFinalizeToolAudit` passes `TestCase` objects instead of `EvalResult` objects.
- `tests/unit/fixtures/test_nodes_then.py` — `tool_results_count()` asserts on `result["tool_results"]`; rename to `judged_cases_count()` asserting on `result["judged_cases"]`. `tool_report_has_results()` asserts on `result["tool_reports"][0].results`; change to `.cases`.
- `tests/unit/fixtures/test_graph_given.py` — `an_initial_state()` includes `"tool_results": []`; change to `"judged_cases": []`.

The pattern: where tests currently pass `EvalResult` instances to `ToolReport(results=...)`, wrap them in `TestCase(payload=..., eval_result=...)`.

### What changes implicitly

- **JSON output format**: `render_json` uses `model_dump`, so the field name in the serialized JSON changes from `"results"` to `"cases"`. Each entry is now a full `TestCase` object (with `payload`, `response`, `error`, `eval_result`) instead of a bare `EvalResult`. This is a format change for `--output` / `-o` JSON files. No backward compatibility concern — this is an internal tool, not a public API.

### What stays unchanged

- `evals/run_judge_eval.py` — the judge isolation eval is unaffected.
- `evals/fixtures/judge_cases.json` — the dataset format stays the same.
- `evals/eval_report.json` format — the aggregated metrics report is unchanged.
- `EvalResult` model — no changes to the LLM output structure.
- `TestCase` model — no changes needed, the `eval_result` field already exists.
- The judge and generator prompts — no prompt changes in this plan.

## Edge cases

- **`eval_result` is None**: A TestCase might not have been judged (e.g., execution error). Consumers must handle `case.eval_result is None` — skip or filter. The JSONL export skips these.
- **Ground truth miss**: Some tool/category pairs may not be in the ground truth (e.g., in non-eval audit runs). The export writes `expected_verdict: null, correct: null` for these.

## Test scenarios

1. **Graph flow unchanged**: existing unit tests for the graph (generate → execute → judge → finalize) should pass after updating fixtures to use `ToolReport(cases=...)`.
2. **Rendering**: existing rendering tests should produce the same markdown output — only the internal data path changes, not the output format.
3. **Metrics**: existing eval metric tests should produce the same results.
4. **JSONL export**: add `tests/unit/test_export.py` with a unit test for `export_judged_cases` — given a list of AuditReports and ground truth, verify it writes the expected JSONL lines with correct `expected_verdict` and `correct` fields. Use the Given/When/Then pattern with `test_export_given.py` / `test_export_then.py` if the helpers abstract something meaningful; inline otherwise.

## Verification

```bash
uv run pytest tests/unit              # All unit tests pass
uv run pytest tests/integration       # Integration tests pass
uv run ruff check .                   # Lint
uv run ruff format .                  # Format
uv run pyright                        # Type check
uv run python -m evals.run_judge_eval # Judge eval still F1 ≥ 0.90
uv run python -m evals.run_evals --runs 1 --budget 10  # E2e produces judged_cases.jsonl
```

After e2e: verify `evals/judged_cases.jsonl` exists, contains all expected fields, and `grep '"correct": false' evals/judged_cases.jsonl` shows the FP cases with their full context.

## Next steps (after this plan)

This plan only implements the export. The iteration workflow that follows:

1. Run e2e eval → inspect `judged_cases.jsonl` for `"correct": false` cases
2. For each FP: read the `description` and `justification` — determine if it's a judge problem or a generator problem
3. Judge-attributable FPs → promote to `judge_cases.json`, iterate on the judge prompt using the isolation eval
4. Generator-attributable FPs (misleading descriptions, irrelevant payloads) → tune `build_attack_generation_prompt`
5. Recall FNs (info_leakage misses) → tune the generator to produce targeted payloads for info_leakage

## Implementation steps

### Step 1: Refactor ToolReport from EvalResult list to TestCase list

**Files** (modify):
- `tests/unit/fixtures/test_nodes_then.py`
- `tests/unit/fixtures/test_nodes_given.py`
- `tests/unit/test_nodes.py`
- `tests/unit/fixtures/test_rendering_given.py`
- `tests/unit/fixtures/test_rendering_then.py`
- `tests/unit/fixtures/test_graph_given.py`
- `tests/unit/fixtures/test_graph_then.py`
- `tests/unit/test_console.py`
- `tests/unit/test_eval_metrics.py`
- `tests/unit/test_graph.py`
- `src/mcp_auditor/domain/models.py`
- `src/mcp_auditor/graph/state.py`
- `src/mcp_auditor/graph/nodes.py`
- `src/mcp_auditor/domain/rendering.py`
- `src/mcp_auditor/cli.py`
- `src/mcp_auditor/console.py`
- `evals/metrics.py`
- `evals/run_evals.py`

**Do**:

1. **Update test fixtures first** (tests will fail until production code catches up):
   - `tests/unit/fixtures/test_nodes_then.py`: Rename `tool_results_count` to `judged_cases_count`, assert on `result["judged_cases"]` instead of `result["tool_results"]`. Change `tool_report_has_results` to assert on `result["tool_reports"][0].cases` instead of `.results`.
   - `tests/unit/test_nodes.py`:
     - `TestGenerateTestCases.test_produces_pending_cases`: call `then.judged_cases_count(result, 0)` instead of `then.tool_results_count(result, 0)`.
     - `TestJudgeResponse.test_produces_eval_result`: pass `"judged_cases": []` instead of `"tool_results": []` in the state dict. Call `then.judged_cases_count(result, 1)`. Add assertion that `result["judged_cases"][0]` is a `TestCase` with `eval_result` populated (not None), and that `eval_result.verdict` matches what the fake LLM returned.
     - `TestFinalizeToolAudit.test_creates_report`: build `TestCase` objects wrapping `EvalResult` via `eval_result` field, pass `"judged_cases": [case1, case2]` instead of `"tool_results": [result1, result2]`. Call `then.tool_report_has_cases(result, 2)` (renamed assertion).
   - `tests/unit/fixtures/test_rendering_given.py`: Change `a_tool_report` to accept `list[EvalResult]`, wrap each into a `TestCase(payload=AuditPayload(...), eval_result=result)` and pass as `ToolReport(cases=...)`. Add import for `TestCase` and `AuditPayload`. The `AuditPayload` fields can be derived from the `EvalResult` (tool_name, category from the result, description="test", arguments=result.payload).
   - `tests/unit/fixtures/test_rendering_then.py`: In `json_has_enum_strings`, change `tool_report["results"]` to `tool_report["cases"]`, and navigate through `case["eval_result"]` to access `verdict` and `severity`.
   - `tests/unit/fixtures/test_graph_given.py`: In `an_initial_state`, rename `"tool_results": []` to `"judged_cases": []`.
   - `tests/unit/fixtures/test_graph_then.py`: In `report_has_results`, rename to `report_has_cases` and assert on `report.cases` instead of `report.results`.
   - `tests/unit/test_console.py`: In `_a_report_with_two_tools`, change `ToolReport(results=[...])` to `ToolReport(cases=[...])` wrapping each `EvalResult` in a `TestCase(payload=AuditPayload(...), eval_result=...)`.
   - `tests/unit/test_eval_metrics.py`: In `_make_report`, change `ToolReport(results=results)` to `ToolReport(cases=[TestCase(payload=AuditPayload(tool_name=r.tool_name, category=r.category, description="test", arguments=r.payload), eval_result=r) for r in results])`.

2. **Update production code** (domain models, then graph, then consumers):
   - `src/mcp_auditor/domain/models.py`: Change `ToolReport.results: list[EvalResult]` to `ToolReport.cases: list[TestCase]`.
   - `src/mcp_auditor/graph/state.py`: Rename `tool_results: list[EvalResult]` to `judged_cases: list[TestCase]` in both `GraphState` and `AuditToolState`. Remove `EvalResult` from imports.
   - `src/mcp_auditor/graph/nodes.py`:
     - `make_judge_response`: attach eval_result to the TestCase via `model_copy`, accumulate into `judged_cases` key instead of `tool_results`. Return `{"judged_cases": existing, "current_case": None}`.
     - `make_finalize_tool_audit`: read from `state["judged_cases"]`, build `ToolReport(tool=tool, cases=cases)`.
     - `make_generate_test_cases`: return `"judged_cases": []` instead of `"tool_results": []`.
     - Remove `EvalResult` from imports (no longer used directly).
   - `src/mcp_auditor/domain/rendering.py`:
     - `_render_summary_section`: `sum(len(tr.results) ...)` becomes `sum(len(tr.cases) ...)`.
     - `_render_tool_section`: iterate `tool_report.cases`, skip if `case.eval_result is None`, pass `case.eval_result` to `_render_result_section`.
     - `_collect_findings`: iterate `tr.cases`, filter `case.eval_result is not None`, then check verdict.
   - `src/mcp_auditor/cli.py`:
     - `_handle_parent_event` (finalize_tool_audit branch): `tool_report.results` becomes `tool_report.cases`, access `case.eval_result.verdict` with None guard.
     - `_handle_subgraph_event` (judge_response branch): `state_update.get("tool_results", [])` becomes `state_update.get("judged_cases", [])`. Last element is a `TestCase` -- access `.eval_result` for tool_name, category, severity, verdict.
   - `src/mcp_auditor/console.py`:
     - `print_summary_table`: `tool_report.results` becomes `tool_report.cases`, access `case.eval_result.verdict` with None guard for pass/fail counting.
   - `evals/metrics.py`:
     - `aggregate_verdicts`: `for result in tool_report.results` becomes `for case in tool_report.cases`, use `case.eval_result` (skip if None).
     - `compute_distribution_coverage`: `{result.category for result in tool_report.results}` becomes `{case.eval_result.category for case in tool_report.cases if case.eval_result}`.
   - `evals/run_evals.py`:
     - `_build_verdict_detail`: `for result in tool_report.results` becomes `for case in tool_report.cases`, use `result = case.eval_result` (skip if None).

3. **Update `tests/unit/test_graph.py`**: all calls to `then.report_has_results(report, N)` become `then.report_has_cases(report, N)`.

**Test**: All existing unit tests pass with the renamed fields and updated data paths. No new test scenarios -- this is a pure refactor.

**Verify**:
```bash
uv run pytest tests/unit
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

### Step 2: Add JSONL export for judged cases

**Files** (create):
- `evals/export.py`
- `tests/unit/test_export.py`

**Files** (modify):
- `evals/run_evals.py`

**Do**:

1. **Write test first** -- `tests/unit/test_export.py`:
   - Test `export_judged_cases` writes correct JSONL with expected fields.
   - Build test data: construct a list of `(run_index, AuditReport)` pairs with known `ToolReport(cases=[...])` entries and a known `GroundTruth` dict.
   - Call `export_judged_cases(runs, ground_truth, report_path)` where `report_path` is a temporary path.
   - Read back the JSONL file, parse each line as JSON.
   - Assert: each line has keys `run_index`, `tool_name`, `tool_description`, `category`, `description`, `arguments`, `response`, `error`, `verdict`, `justification`, `expected_verdict`, `correct`.
   - Assert: `correct` is `True` when verdict matches ground truth, `False` when it doesn't, `None` when there's no ground truth for that key.
   - Assert: cases with `eval_result is None` are skipped (not written to JSONL).
   - Given/When/Then helpers are optional -- inline if the setup and assertions are straightforward.

2. **Create `evals/export.py`**:
   - `export_judged_cases(runs: list[tuple[int, AuditReport]], ground_truth: GroundTruth, report_path: Path) -> None`
   - Derives `export_path = report_path.with_name("judged_cases.jsonl")`.
   - Iterates runs, tool_reports, cases. Skips cases where `eval_result is None`.
   - For each case, looks up `ground_truth.get((result.tool_name, result.category))` for expected verdict.
   - Writes one JSON line per case with all fields specified in the plan.

3. **Modify `evals/run_evals.py`**:
   - Create a `EvalRunResult` dataclass (or named tuple) with fields: `report: EvalReport`, `runs: list[tuple[int, AuditReport]]`, `ground_truth: GroundTruth`. This follows the coding standard of extracting a Value Object when parameters accumulate.
   - Change `run_evals()` return type from `EvalReport` to `EvalRunResult`.
   - Inside `run_evals()`, accumulate `(i, audit_report)` pairs in a list alongside `run_details`. This requires capturing `audit_report` from `_run_one_eval` (it's already returned as part of the tuple). Also capture `merged_ground_truth` from the last `_run_one_eval` call (or accumulate it separately -- since `_run_one_eval` returns `merged_ground_truth` each time and it's the same across runs, just keep the last one). Actually, ground truth is deterministic (from `HONEYPOTS`), so accumulate it once outside the loop by merging all `honeypot.ground_truth` dicts.
   - Return `EvalRunResult(report=eval_report, runs=accumulated_runs, ground_truth=merged_ground_truth)`.
   - In `main()`: unpack `EvalRunResult`, call `export_judged_cases(result.runs, result.ground_truth, Path(args.report))` after writing the eval report JSON. Import `export_judged_cases` from `evals.export`.

**Test**:
- `test_export_writes_correct_jsonl`: given 2 runs with 1 tool each, 2 cases per tool (one PASS matching ground truth, one FAIL not in ground truth), verify JSONL has 4 lines with correct `correct` values.
- `test_export_skips_unjudged_cases`: given a TestCase with `eval_result=None`, verify it is not in the output.
- `test_export_handles_missing_ground_truth`: given a case whose tool/category pair is not in ground truth, verify `expected_verdict` is null and `correct` is null.

**Verify**:
```bash
uv run pytest tests/unit
uv run ruff check .
uv run ruff format --check .
uv run pyright
```
