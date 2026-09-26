# The generator completes the categories a batch misses

## Context

[ADR 021](../docs/adr/021-gpt-6-luna-default.md) (Accepted, `2cd755f`) decides: "When a generated batch still lacks a category after its retry, the auditor asks for the missing categories alone, instead of reporting the gap and auditing the tool without them." The need holds for any model: on 2026-09-25, Gemini 3.5 Flash-Lite left a batch of `list_items` without `error_handling` after the retry, and `gpt-6-luna` at `none` returned 2 generated batches out of 55 without `resource_abuse` in the probe run.

Today, `make_generate_test_cases` (`src/mcp_auditor/graph/nodes.py`) calls `_generate_with_one_retry`: it generates a batch, checks it with `find_coverage_gap` (`src/mcp_auditor/domain/coverage.py`), asks for the whole batch once more if it is incomplete, and keeps the retried batch with its gap. The gap reaches the tool report and is shown in the console, the Markdown report and the JSON report. The tool is then audited without the missing categories.

This plan adds one completion call after the retry. It does not change the retry, the gap check, the reporting of a gap, the prompt text, or the default model (a separate change).

## Approach

After the retry, when the retried batch still has a gap with missing categories, one more call asks for those categories alone, with the existing generation prompt restricted to them. Its cases in those categories are appended to the retried batch, and the gap is computed again on the merged batch. What is still missing after that stays reported as a gap, as today.

- **One completion call, no loop.** The completion is the last attempt. A model that cannot fill a category in three calls gets reported, and the audit goes on.
- **Its share of the budget per category still needed**: `max(1, budget // len(categories))` cases for each, 2 at budget 10, and never more categories than the batch needs to reach `min(budget, len(categories))` (see `completion_size`). A completed category weighs as much as the others in the audit. The total goes over the budget by those cases (12 at budget 10 with one missing category).
- **The prompt is `build_attack_generation_prompt`** with `categories` set to the missing ones and `budget` set to the number of cases asked for. It already distributes cases over the categories it is given, and it carries the tool, the attack context and the non-destructive constraint. No new prompt function.
- **Only cases in the missing categories are kept from the completion.** A case in a category the batch already covers would add to the overshoot without closing any gap.
- **A gap with no missing category is not completed.** A batch with all its categories but fewer cases than the budget keeps today's behavior: retried once, then reported.

## Files to modify

### `src/mcp_auditor/graph/nodes.py`

`make_generate_test_cases` calls a renamed helper, `_generate_covering_batch`, which does the first call, the retry and the completion, and returns the batch, its gap and the usages of every call made:

```python
async def _generate_covering_batch(
    llm: LLMPort, request: GenerationRequest
) -> tuple[TestCaseBatch, CoverageGap | None, list[TokenUsage]]:
    batch, usage = await llm.generate_structured(build_attack_generation_prompt(...), TestCaseBatch)
    gap = find_coverage_gap(batch, request.budget, request.categories)
    if gap is None:
        return batch, None, [usage]
    retried, retry_usage = await llm.generate_structured(<same prompt>, TestCaseBatch)
    gap = find_coverage_gap(retried, request.budget, request.categories)
    if gap is None or not gap.missing_categories:
        return retried, gap, [usage, retry_usage]
    added, completion_usage = await _complete_categories(llm, request, gap.missing_categories)
    completed = TestCaseBatch(cases=[*retried.cases, *added])
    return completed, find_coverage_gap(completed, request.budget, request.categories), [usage, retry_usage, completion_usage]
```

The sketch shows the flow, not the final shape: the helper takes more than three values (the LLM, the tool, the budget, the categories, the attack context), so a small frozen dataclass in `graph/nodes.py` names the grouping, `GenerationRequest(tool, budget, categories, attack_context)`, and builds its own prompt for a set of categories and a case count. The helper stays under 20 lines, splitting the completion into `_complete_categories`:

```python
async def _complete_categories(
    llm: LLMPort, request: GenerationRequest, missing: list[AuditCategory]
) -> tuple[list[AuditPayload], TokenUsage]:
    size = completion_size(request.budget, request.categories, missing)
    prompt = request.prompt_for(missing, size)
    completion, usage = await llm.generate_structured(prompt, TestCaseBatch)
    return [case for case in completion.cases if case.category in missing][:size], usage
```

`completion_size` is a pure function in `src/mcp_auditor/domain/coverage.py`, beside `find_coverage_gap`, unit-tested in `tests/unit/test_coverage.py`. The categories still needed are the ones that bring the batch up to the `min(budget, len(categories))` distinct categories `find_coverage_gap` expects, which is fewer than the missing list when the budget is below the number of categories (`missing` lists every uncovered category). Each needed category gets its share of the budget:

```python
def completion_size(budget: int, categories: list[AuditCategory], missing: list[AuditCategory]) -> int:
    covered = len(categories) - len(missing)
    still_needed = min(budget, len(categories)) - covered
    return still_needed * max(1, budget // len(categories))
```

The prompt still names every missing category, so the model picks which ones to write when fewer are needed, and the kept cases are cut to `size`. At budget 10 with one missing category, `size` is 2. At budget 3 with 2 categories covered, `size` is 1, where asking for every missing category would have taken the batch to 5 cases.

It takes the missing categories rather than the retried batch and its gap, and returns the cases it keeps, so it stays at three arguments and `_generate_covering_batch` does the merge.

`GenerationRequest.prompt_for(categories, budget)` returns `build_attack_generation_prompt(tool=..., budget=budget, categories=categories, attack_context=...)`. The first call and the retry use `request.prompt_for(request.categories, request.budget)`, which is today's prompt, unchanged.

`find_coverage_gap`, `CoverageGap`, the state keys and `build_tool_report` do not change.

### `tests/unit/test_nodes.py` and `tests/unit/support/test_nodes_given.py`

In `TestGenerateTestCases` (the class holding the retry tests):

- `test_a_retry_still_incomplete_is_kept_with_its_gap` changes: the `FakeLLM` gets a third response, a completion that covers none of the missing categories, and the gap stays as today, with 3 token usages.
- New: a retry missing a category is completed with that category's cases, appended after the retried cases, with no gap and 3 token usages.
- New: a completion that fills one of two missing categories leaves a gap naming the other one.
- New: cases of a completion in a category the batch already covers are dropped.
- New: a retry with all its categories but too few cases is not completed (2 token usages, gap with no missing category, as today).
- The first-call and retry tests stay as they are.

A helper `a_batch_covering(categories, per_category)` in the given module builds a batch for exact category sets, if `a_batch_of` cannot express the scenario. No assertion on the prompt text: the prompt function is tested in `test_prompts.py`, and the node tests assert on the batch, the gap and the usage count.

### `tests/unit/support/test_graph_given.py`

Two graph tests script a retried batch that still misses categories, so the node now makes a third LLM call their `FakeLLM` does not hold. Each gets a completion response that fills none of the missing categories (e.g. `a_complete_batch(1)`, a single `input_validation` case the batch already covers, which the node drops), so their assertions stay as they are:

- `a_fake_llm_whose_first_tool_batch_stays_short`: `first_tool = [short, short, <completion>, *short_judgments, AttackContext()]`. Without it the completion pops a `Judgment` and `FakeLLM` raises `TypeError` (`test_a_batch_still_short_after_retry_is_flagged_on_its_tool_only`).
- `a_fake_dry_run_llm_whose_batch_stays_short`: a third response after the two short batches. Without it the completion pops an empty deque and raises `IndexError` (`test_a_dry_run_carries_the_coverage_gap_to_its_tool_report`).

`tests/unit/test_graph.py` itself does not change.

### Living docs

- `CHANGELOG.md`, `[Unreleased]`, *Changed*: the bullet that begins "A generated test case batch that holds fewer cases than the budget" now says that a batch still missing categories after the retry is completed with the missing categories alone, their share of the budget each, and that only what is still missing after that is flagged. The same bullet says that the flag now reads "7 cases generated for 10 requested" instead of "7 of 10 requested cases generated after one retry".
- `README.md`, step 2 of "What it does": it says "a tool whose batch is still incomplete after that retry is flagged", which the completion makes false. It now says that a batch still missing categories after the retry is asked for those categories alone, and that a tool whose batch is still incomplete after that is flagged.

### `src/mcp_auditor/domain/rendering.py`

`describe_coverage_gap` drops "after one retry", which a gap no longer follows alone, and no longer reads "12 of 10" when a completion took the batch over the budget: it renders `f"{gap.received_cases} cases generated for {gap.requested_cases} requested"`, then `, missing categories: ...` as today. The console, the dry run and the Markdown report pick it up, since they all call it. A test in `tests/unit/test_rendering.py` pins the new text for a gap with and without missing categories, written first. The existing `test_markdown_flags_a_coverage_gap_right_under_the_tool_heading` asserts `"7 of 10" in gap_line` and changes to the new wording (`"7 cases generated for 10 requested"`). So do `test_summary_warns_about_a_tool_with_a_coverage_gap` and `test_ci_mode_summary_warns_about_a_tool_with_a_coverage_gap` in `tests/unit/test_console_display.py`, which assert `"7 of 10" in warning`.



## What stays unchanged

- `find_coverage_gap` and its rule, `CoverageGap`, and where a gap is shown (console, dry run, Markdown, the `coverage_gap` entry in JSON).
- The retry of the whole batch on a first incomplete batch.
- `build_attack_generation_prompt` and every prompt text.
- The judge, the chains, the context extraction, the graph wiring, the state schema.
- The probe (`evals/`), which replays single calls and never runs the node.
- The default model and `config.py`.

## Edge cases

- **Budget below the number of categories** (e.g. budget 3): `find_coverage_gap` expects `min(budget, 5)` distinct categories and lists missing ones only when fewer are covered. The completion asks for `completion_size`, 1 case at budget 3 with 2 categories covered, so the merged batch holds at most one case over the budget.
- **Completion returns nothing in the missing categories**: the merged batch equals the retried one, the gap is the retried batch's gap, recomputed.
- **Completion covers some missing categories**: the gap lists the remaining ones, with `received_cases` counting the merged batch.
- **`UnparseableOutput` on the completion call**: it propagates as it does today for the first call and the retry. No new error handling.
- **Merged batch over the budget**: expected. `find_coverage_gap` compares `received >= budget`, so the case count part of the gap clears.

## Verification

```bash
uv run pytest tests/unit
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

## Commit message

One commit, a change to the system under test. The message says where it lands (the generation node only, no prompt text, fixture, label or scoring change), why it holds without any measurement (an incomplete batch leaves the tool audited without a category, whatever the model), how it was found (the probe's incomplete batches and the Gemini 3.5 batch left without `error_handling` on 2026-09-25), and points at ADR 021. It names no plan, step or phase.

## Due diligence record

What the plan-diligence pass concluded about the external facts this plan cites or defers, read by the implementation-phase fact check. It records what was concluded once, not what is true now: no pass may treat a line here as a reason to skip a verification. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- No external facts to verify: the plan cites no third-party API, library, CI action or version that the code will carry, and defers none. The model names in Context (Gemini 3.5 Flash-Lite, `gpt-6-luna`) are past observations from local eval runs, not values the change writes.

## Implementation steps

### Step 1: Complete the categories a retried batch misses, and reword the gap

- **Files**:
  - Modify `tests/unit/test_coverage.py`, `tests/unit/test_rendering.py`, `tests/unit/test_console_display.py`, `tests/unit/test_nodes.py`, `tests/unit/support/test_nodes_given.py`, `tests/unit/support/test_graph_given.py`
  - Modify `src/mcp_auditor/domain/coverage.py`, `src/mcp_auditor/domain/rendering.py`, `src/mcp_auditor/graph/nodes.py`
  - Modify `CHANGELOG.md` (`[Unreleased]`, *Changed*), `README.md` (step 2 of "What it does")
- **Do** (tests first, run them red, then production code):
  1. `tests/unit/test_coverage.py`: tests for `completion_size(budget, categories, missing) -> int` (not yet existing, import fails red).
  2. `tests/unit/test_rendering.py`: a test pinning `describe_coverage_gap` for a gap with missing categories (`"7 cases generated for 10 requested, missing categories: ..."`) and one without (`"7 cases generated for 10 requested"`, no "missing categories", no "after one retry"). Change `test_markdown_flags_a_coverage_gap_right_under_the_tool_heading` from `"7 of 10"` to `"7 cases generated for 10 requested"`.
  3. `tests/unit/test_console_display.py`: `test_summary_warns_about_a_tool_with_a_coverage_gap` and `test_ci_mode_summary_warns_about_a_tool_with_a_coverage_gap` assert `"7 cases generated for 10 requested"` instead of `"7 of 10"`.
  4. `tests/unit/support/test_nodes_given.py`: add `a_batch_covering(categories, per_category)` only if `a_batch_of` cannot express the scenarios below.
  5. `tests/unit/test_nodes.py`, class `TestGenerateTestCases`: change `test_a_retry_still_incomplete_is_kept_with_its_gap` (third `FakeLLM` response, a completion covering none of the missing categories, same gap, 3 token usages) and add the four new tests listed under Test. Assert on the batch (pending cases), the gap and the usage count only, never on prompt text. `test_nodes.py` is already 335 lines: keep additions tight, move setup into the given module where it abstracts something.
  6. `tests/unit/support/test_graph_given.py`: add a completion response that fills no missing category (e.g. `a_complete_batch(1)`) as the third LLM response in `a_fake_llm_whose_first_tool_batch_stays_short` (`first_tool = [short, short, <completion>, *short_judgments, AttackContext()]`) and in `a_fake_dry_run_llm_whose_batch_stays_short` (after the two short batches). `tests/unit/test_graph.py` does not change.
  7. `src/mcp_auditor/domain/coverage.py`: add, beside `find_coverage_gap`:
     ```python
     def completion_size(budget: int, categories: list[AuditCategory], missing: list[AuditCategory]) -> int:
         covered = len(categories) - len(missing)
         still_needed = min(budget, len(categories)) - covered
         return still_needed * max(1, budget // len(categories))
     ```
  8. `src/mcp_auditor/domain/rendering.py`: `describe_coverage_gap` renders `f"{gap.received_cases} cases generated for {gap.requested_cases} requested"`, then `, missing categories: ...` as today.
  9. `src/mcp_auditor/graph/nodes.py`:
     - Frozen dataclass `GenerationRequest(tool, budget, categories, attack_context)` with `prompt_for(categories, budget) -> str` returning `build_attack_generation_prompt(tool=self.tool, budget=budget, categories=categories, attack_context=self.attack_context)`.
     - `make_generate_test_cases` builds a `GenerationRequest` (categories `list(AuditCategory)`) and calls `_generate_covering_batch(llm, request)`; the returned state keys are unchanged.
     - Rename `_generate_with_one_retry` to `_generate_covering_batch(llm, request) -> tuple[TestCaseBatch, CoverageGap | None, list[TokenUsage]]`: first call and retry with `request.prompt_for(request.categories, request.budget)`; return after the first call if no gap; after the retry return `retried, gap, [usage, retry_usage]` if the gap is `None` or has no missing categories; otherwise call `_complete_categories`, merge `TestCaseBatch(cases=[*retried.cases, *added])`, recompute the gap on the merged batch, return three usages. Keep it under 20 lines.
     - `_complete_categories(llm, request, missing) -> tuple[list[AuditPayload], TokenUsage]`: `size = completion_size(request.budget, request.categories, missing)`, one `generate_structured(request.prompt_for(missing, size), TestCaseBatch)`, keep `[case for case in completion.cases if case.category in missing][:size]`. No new error handling (`UnparseableOutput` propagates).
     - `find_coverage_gap`, `CoverageGap`, state keys, `build_tool_report` and every prompt text stay unchanged. Newspaper order: public factory, then `_generate_covering_batch`, then `_complete_categories`; the dataclass above its first use.
  10. Living docs: `CHANGELOG.md` `[Unreleased]` *Changed*, the bullet beginning "A generated test case batch that holds fewer cases than the budget": a batch still missing categories after the retry is completed with the missing categories alone, their share of the budget each, and only what is still missing after that is flagged; the flag now reads "7 cases generated for 10 requested" instead of "7 of 10 requested cases generated after one retry". `README.md`, step 2 of "What it does": replace "a tool whose batch is still incomplete after that retry is flagged" with: a batch still missing categories after the retry is asked for those categories alone, and a tool whose batch is still incomplete after that is flagged. No edit to `plans/` or `docs/adr/`.
- **Test**:
  - `completion_size`: budget 10, 5 categories, 1 missing -> 2. Budget 10, 2 missing -> 4. Budget 3, 3 missing (2 covered) -> 1. Budget 3, all 5 missing -> 3. Budget 7, 1 missing -> 1.
  - `describe_coverage_gap`: with missing categories and without, new wording, no "after one retry".
  - Node, retry missing a category, completion supplies that category: pending cases are the retried cases followed by the completion's cases in that category, gap `None`, 3 token usages.
  - Node, retry missing two categories, completion fills one: gap names only the other, `received_cases` counts the merged batch.
  - Node, completion holding cases in a category the batch already covers: those cases are dropped (pending cases equal the retried cases plus only the missing-category cases).
  - Node, retry with every category but fewer cases than the budget: no completion call, 2 token usages, gap with empty `missing_categories`.
  - Node, completion covering none of the missing categories (changed existing test): batch equals the retried one, same gap as before, 3 token usages.
  - First-call and retry tests unchanged and green. Graph tests `test_a_batch_still_short_after_retry_is_flagged_on_its_tool_only` and `test_a_dry_run_carries_the_coverage_gap_to_its_tool_report` green with unchanged assertions.
- **Verify**:
  - `uv run pytest tests/unit` (new tests red before production code, all green after)
  - `uv run pytest` all green (the Docker integration test may skip)
  - `uv run ruff check .` clean
  - `uv run ruff format --check .` clean
  - `uv run pyright` 0 errors
