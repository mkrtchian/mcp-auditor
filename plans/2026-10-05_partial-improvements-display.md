# Show partial improvements in the outcome tables

## Context

The outcome tables of the e2e evals and of the judge eval list the cells (cases, for the judge) that left `unchanged`. One movement never reaches them. A cell stable and incorrect in every baseline run (a planted flaw always missed, a PASS cell always alarmed, a FAIL case the judge always passes) that comes out correct in some runs of this one, but not all, stays `unchanged`: `_compare_cell` (`evals/gate.py`) gives `improved` only to a run correct in every run. The gate is right to ignore it, since nothing protected moved. But the console then hides the one thing a change aimed at a missed detection produces first.

A judge run at `1cc7131` showed it: the honeypot case `f9ebef7823fc1caf` (`delete_record` × `input_validation`, labeled FAIL), judged PASS in all six baseline runs, came out `FPF`, detected twice out of three, and the table said nothing. The next change planned on the judge is a prompt realignment aimed at exactly those always-missed FAIL cases, so the display should show partial progress before it starts.

The other movements are already visible: a stable and correct cell that moves is a `flip` and is replayed, an unstable baseline cell not always correct is `inconclusive`. The gap is the stable and incorrect baseline cell that is correct in some runs only.

This is display only. `compare`, the gate, the replay rule, the baselines, their conditions and the JSON reports do not change: not an instrument change, no labeling log entry, no baseline reset.

## Decisions

- The mark is `partial`, a display label computed beside the gate's `CellOutcome`, never a `CellOutcome` value. The gate never sees it.
- Both suites: the e2e outcome table and the judge outcome table gain `partial` rows. The judge `Cases:` count line counts `partial` apart from `unchanged`.
- The e2e grid does not change. Its boxes keep showing the baseline's state, with a gate outcome over it when there is one. The grid stays the map of the baseline, and the partial movement shows in the outcome table under it.

## Definition

A cell (case) is a partial improvement when, against a baseline that covers it:

- every baseline run observed it, and all of them incorrectly (`CellState.STABLE_INCORRECT` under `classify`), and
- at least one run of this one observed it correctly (the observation equals the expected verdict), and
- not every run of this one did (otherwise the gate already says `improved`).

An uncovered observation is never correct. A cell some run did not record (`run.get(cell)` missing) counts as uncovered, as the letters already do.

## Files to modify

### `evals/cell_grid.py`

- A display label constant `PARTIAL = "partial"`.
- `partial_improvements[K](baseline_runs: list[dict[K, Observation]], candidate_runs: list[dict[K, Observation]], ground_truth: dict[K, EvalVerdict]) -> set[K]`: the keys matching the definition above, built on `classify(baseline_runs, ground_truth)` from `evals/gate.py` (`dict`, not `Mapping`: `classify` takes a `dict`, and pyright strict refuses a `Mapping` there). Generic in `K`, like `compare` and `classify`, so the honeypot cells (`Cell`) and the judge cases (`str`) share it. Placed right below `outcome_rows`, its caller in this module, as `observation_letters` sits right below `_letters`.
- `OutcomeRow.outcome` becomes `str` (a `CellOutcome` value, or `PARTIAL`). `CellOutcome` is a `StrEnum`, so existing values keep printing the same.
- `outcome_rows(ground_truth, baseline_runs, run)`: keeps today's rows, and adds one row per key of `partial_improvements(baseline_runs, run.runs, ground_truth)` whose comparison is `unchanged`, with outcome `PARTIAL` and replays `-`. Rows stay sorted by cell key as today. `run.runs` is keyed by `Cell` and the comparisons by `cell_key(cell)`: convert with `cell_key` as the existing code does.

### `evals/eval_display.py`

- `print_summary`: after the existing `P pass, F fail, - not covered` line, when any row is `partial`, one more line: `partial: wrong in every baseline run, right in some runs of this one, not gated`.

### `evals/judge_outcomes.py`

- `JudgeOutcomeRow.outcome` becomes `str`, as `OutcomeRow`.
- `judge_outcome_rows`: adds a row per partial case whose comparison in `result.gate.cases` is `unchanged`, as the e2e does (outcome `PARTIAL`, replays `-`, cause `-`), computed with `partial_improvements(result.baseline.runs, result.runs, ground_truth)`. Restricting to the `unchanged` comparisons keeps one row per case and keeps the existing tests, whose `gate.cases` are hand-built, free of rows computed from runs they did not list. The ground truth comes from `ground_truth_of(fixture)` (`evals/judge_fixture.py`), which leaves the `unspecified` cases out, as the gate does. Sorting: `partial` comes right after `improved` in the outcome order, then by case id. `_OUTCOME_ORDER` becomes a `list[str]` holding `PARTIAL` after `CellOutcome.IMPROVED`, since `list(CellOutcome).index("partial")` would raise.
- `outcome_counts`: a partial case counts under `partial` and not under `unchanged`, so the counts still add up to the compared cases. The order is the `CellOutcome` order with `partial` right after `improved`. The function needs the fixture's ground truth for that, so it takes the fixture too: `outcome_counts(result, fixture)`, and `case_outcomes` passes it. Its return type and `CaseOutcomes.counts` become `dict[str, int]`.

### `evals/judge_display.py`

- `_print_case_outcomes`: after the `P pass, F fail, - no verdict` line, the same `partial: ...` line as the e2e when any row is `partial`.

### Living docs

- `CHANGELOG.md` `[Unreleased]`, `### Added`: the outcome tables of the e2e evals and of the judge eval list as `partial` a cell or case wrong in every baseline run and right in some runs of the current one, which the gate does not gate and used to leave unlisted, and the judge's case count shows them apart.
- `CONTRIBUTING.md`: the judge section ("Against a baseline, the summary counts the cases per outcome and lists in a table those that left `unchanged`...") gets one clause naming `partial`. The e2e section only describes the grid, not the outcome table: no change there.
- `README.md`, `CLAUDE.md`: no change expected (no command, flag or env var).

## What stays unchanged

- `evals/gate.py` (`compare`, `_compare_cell`, `classify`, `settle`, `CellOutcome`, `ReplayRule`), `evals/judge_gate.py`, the e2e gate, both baselines and their files, the recording, the declared flips.
- The JSON reports of both suites: `partial` is not written. The runs it is computed from are already in them.
- The e2e grid (`cell_grid`, `_rows`, `_box`, `CellTag`, the legend of the grid).
- The exit codes, the verdict panels, the protected counts line.

## Edge cases

- No baseline, or `--ungated`: no comparison, no rows, no `partial` (as today).
- Exploratory baseline: rows are computed as today, `partial` included.
- A cell the baseline did not record (`not_recorded`): `classify` gives it no state, so it is never `partial`.
- An unstable baseline cell: not `partial` (`inconclusive` or `unchanged` as today).
- A stable incorrect cell correct in every run: `improved` as today, not `partial`.
- A stable incorrect cell whose runs are correct once and uncovered otherwise: `partial`.
- A stable incorrect cell whose runs are only incorrect or uncovered: `unchanged`, no row.
- A judge case labeled `unspecified`: out of the ground truth, never `partial`.

## Test scenarios

Test first.

`tests/unit/test_eval_cell_grid.py` (with its `support/test_eval_cell_grid_given.py`):
- `partial_improvements`: a stable incorrect cell right in one run of three is returned. Right in every run, it is not. Right in none, it is not. Right once and uncovered otherwise, it is. A stable correct cell and an unstable cell are never returned. A cell missing from the baseline runs is not returned.
- `outcome_rows`: a partial cell with an `unchanged` comparison gets a row with outcome `partial`, its baseline and run letters, and replays `-`, in cell key order among the other rows. The existing outcome row tests keep passing.

`tests/unit/test_judge_outcomes.py` (with `tests/unit/support/test_judge_outcomes_given.py`, which needs a new case labeled FAIL, judged PASS in its baseline runs and `FPF` in the run, added to `a_judge_fixture` and to the runs of `a_result`. Today's cases cannot serve: `FLIPPED_CASE` is labeled PASS and `NEW_CASE` is absent from the baseline):
- A case judged PASS in every baseline run, labeled FAIL, judged `FPF` in the run, gets a `partial` row with cause `-` and replays `-`, sorted after `improved` rows.
- The counts put it under `partial` and not `unchanged`, and the counts still add up to the compared cases.
- An `unspecified` case never shows as `partial`.

Display tests (`tests/unit/test_eval_display.py`, `tests/unit/test_judge_display.py`): a summary with a `partial` row prints the `partial:` legend line, and a summary without one does not.

## Verification

```bash
uv run pytest tests/unit -n auto
uv run pytest tests/integration -n auto
uv run pyright
uv run ruff check .
uv run ruff format --check .
uv run python -m evals.run_judge_eval   # needs OPENAI_API_KEY: a case like f9ebef7823fc1caf shows as partial when judged FAIL in some runs only
```

The live run is the only real-LLM step. A partial row shows only when the judge happens to detect an always-missed case in some runs, so a run without one proves nothing against the change.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, kept so the implementation-phase fact check can read it. It records what was concluded once, not what is true now: no pass may treat a line here as a reason to skip a verification. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- No external facts to verify: the plan cites and defers no third-party API, library version, CI action or platform behavior. Every name it uses is local to this repository and was checked against the source.

## Implementation steps

### Step 1: `partial_improvements` and the e2e `partial` rows

- **Files**:
  - `tests/unit/test_eval_cell_grid.py` (modify)
  - `tests/unit/support/test_eval_cell_grid_given.py` (modify, only if a helper actually abstracts something)
  - `tests/unit/test_eval_display.py` (modify)
  - `tests/unit/support/test_eval_display_given.py` (modify: a `GateGrid` carrying outcome rows)
  - `evals/cell_grid.py` (modify)
  - `evals/eval_display.py` (modify)
- **Do**:
  1. Tests first (see **Test**), run them, confirm they fail.
  2. `evals/cell_grid.py`:
     - `PARTIAL = "partial"` constant.
     - `OutcomeRow.outcome: str` (a `CellOutcome` value or `PARTIAL`).
     - `partial_improvements[K](baseline_runs: list[dict[K, Observation]], candidate_runs: list[dict[K, Observation]], ground_truth: dict[K, EvalVerdict]) -> set[K]`, placed right below `outcome_rows`. Built on `classify(baseline_runs, ground_truth)`: keep the keys whose state is `CellState.STABLE_INCORRECT`, and whose candidate observations (`run.get(key, Observation.UNCOVERED)`, so a missing key is uncovered) equal `Observation(ground_truth[key].value)` in at least one run but not in all. Uncovered never equals the expected verdict. Use `dict`, not `Mapping` (pyright strict, `classify` takes a `dict`). Check that `classify` returns no state for a key absent from the baseline runs (`not_recorded`), so such a key is never returned.
     - `outcome_rows`: keep today's rows, and add a row with outcome `PARTIAL` and replays `-` for every key of `partial_improvements(baseline_runs, run.runs, ground_truth)` whose comparison in `run.comparisons[cell_key(cell)]` is `CellOutcome.UNCHANGED`. Baseline and run letters as for the other rows. Rows stay sorted by cell key (`cell_key(cell)`), the partial ones interleaved with the others. Keep the function under ~20 lines (e.g. a predicate `_listed(key, comparison, partial_keys)` or computing the set of partial keys once before the comprehension).
  3. `evals/eval_display.py`, `print_summary`: after `P pass, F fail, - not covered`, when any row's outcome is `PARTIAL`, print `partial: wrong in every baseline run, right in some runs of this one, not gated`. Import `PARTIAL` from `evals.cell_grid`. The grid (`_rows`, `_box`, `CellTag`, legend) does not change.
  4. Run `uv run pyright`: `run_evals.py` builds the `GateGrid` from `outcome_rows` and needs no change, but confirm nothing else relied on `OutcomeRow.outcome` being a `CellOutcome`.
- **Test**:
  - `test_eval_cell_grid.py`, `partial_improvements` (use `given.baseline_runs` overrides, with `None` for a run that lacks the cell):
    - `PLANTED_CELL` baseline `[PASS, PASS, PASS]` (stable incorrect), candidate `[FAIL, PASS, PASS]` -> `{PLANTED_CELL}`.
    - same baseline, candidate `[FAIL, FAIL, FAIL]` -> empty (that is `improved`).
    - same baseline, candidate `[PASS, PASS, PASS]` -> empty.
    - same baseline, candidate `[FAIL, UNCOVERED, None]` -> `{PLANTED_CELL}`.
    - a stable correct cell and an unstable baseline cell (`[FAIL, PASS, FAIL]` on `PLANTED_CELL`), each with a mixed candidate, are never returned (one parametrized test is enough).
    - a cell missing from every baseline run (`[None, None, None]`) with a mixed candidate is not returned.
  - `test_eval_cell_grid.py`, `outcome_rows`: a stable incorrect `SAFE_CELL` (baseline `[FAIL, FAIL, FAIL]`, candidate `[PASS, FAIL, FAIL]`) with an `UNCHANGED` comparison, beside a `REGRESSION` on `SECOND_SAFE_CELL`, gives an `OutcomeRow(outcome="partial", cell="list_dir/error_handling", planted=False, baseline="FFF", run="PFF", replays="-")` placed in cell key order among the other rows. The existing `test_outcome_rows_list_the_changed_cells_sorted_with_their_observations_and_replays` keeps passing unchanged.
  - `test_eval_display.py`: a summary whose grid holds a `partial` row prints the `partial: wrong in every baseline run, right in some runs of this one, not gated` line, and a summary whose grid holds only a non-partial row does not print `partial:`.
- **Verify**:
  - `uv run pytest tests/unit -n auto`: all green.
  - `uv run pyright`: 0 errors.
  - `uv run ruff check .` and `uv run ruff format --check .`: clean.

### Step 2: judge `partial` rows, counts and legend, living docs

- **Files**:
  - `tests/unit/support/test_judge_outcomes_given.py` (modify)
  - `tests/unit/test_judge_outcomes.py` (modify)
  - `tests/unit/support/test_judge_display_given.py` (modify)
  - `tests/unit/test_judge_display.py` (modify)
  - `evals/judge_outcomes.py` (modify)
  - `evals/judge_display.py` (modify)
  - `CHANGELOG.md`, `CONTRIBUTING.md` (modify)
- **Do**:
  1. Fixtures first. In `test_judge_outcomes_given.py`, add `PARTIAL_CASE = a_case(label=CaseLabel.FAIL, ...)` with its own distinct tool/category/description and an origin (e.g. `cell delete_record/input_validation` style, but with a distinct target so its id differs), and `PARTIAL_ID`. Add it to `a_judge_fixture()`, to every baseline run of `a_result` judged `P`, and to the runs of `a_result` judged `F, P, F` (letters `FPF`). Also add an `UNSPECIFIED_CASE` labeled `CaseLabel.UNSPECIFIED` with the same `PPP` baseline and `FPF` run, to check it never shows as partial. Update the `a_result` docstring. Existing tests whose `gate.cases` are hand-built must keep passing: they do not list the new cases, so no row is computed for them.
  2. Tests (see **Test**), run them, confirm they fail.
  3. `evals/judge_outcomes.py`:
     - `JudgeOutcomeRow.outcome: str`, `CaseOutcomes.counts: dict[str, int]`.
     - `_OUTCOME_ORDER: list[str]`: the `CellOutcome` values with `PARTIAL` inserted right after `CellOutcome.IMPROVED`.
     - A private helper computing the partial case ids once: `partial_improvements(result.baseline.runs, result.runs, ground_truth_of(fixture))` (from `evals.cell_grid` and `evals.judge_fixture`), empty without a baseline.
     - `judge_outcome_rows`: a case whose comparison in `result.gate.cases` is `UNCHANGED` and that is partial gets a row with outcome `PARTIAL`, replays `-`, cause `-`, and the usual baseline/run letters. Sorted by `_OUTCOME_ORDER.index(row.outcome)` then case id.
     - `outcome_counts(result, fixture) -> dict[str, int]`: a partial `unchanged` case counts under `PARTIAL`, not `UNCHANGED`. Order follows `_OUTCOME_ORDER`, zeros left out, counts sum to `len(result.gate.cases)`. `case_outcomes` passes the fixture.
     - Update the module docstring (the table now also lists the partial cases).
  4. `evals/judge_display.py`, `_print_case_outcomes`: after `P pass, F fail, - no verdict`, when any row's outcome is `PARTIAL`, print the same line as the e2e: `partial: wrong in every baseline run, right in some runs of this one, not gated`.
  5. Living docs:
     - `CHANGELOG.md` `[Unreleased]` `### Added`: the outcome tables of the e2e evals and of the judge eval list as `partial` a cell or case wrong in every baseline run and right in some runs of the current one, which the gate does not gate and used to leave unlisted, and the judge's case count shows them apart.
     - `CONTRIBUTING.md` line starting "Against a baseline, the summary counts the cases per outcome...": add one clause saying the table also lists as `partial` a case wrong in every baseline run and right in some runs of this one, counted apart from `unchanged`.
     - `README.md`, `CLAUDE.md`: no change.
- **Test**:
  - `test_judge_outcomes.py`:
    - with `gate.cases` holding `PARTIAL_ID: UNCHANGED` and `FLIPPED_ID: IMPROVED` (or another outcome placed before `partial`, and one after it such as `FLIP` on `STEADY_ID`), the partial row is `JudgeOutcomeRow(outcome="partial", case=PARTIAL_ID, ..., label=CaseLabel.FAIL, baseline="PPP", run="FPF", replays="-", cause="-")`, sorted after the `improved` row and before the later outcome.
    - counts: `PARTIAL_ID: UNCHANGED`, `STEADY_ID: UNCHANGED`, `NEW_ID: NOT_RECORDED` give `[("unchanged", 1), ("partial", 1), ("not_recorded", 1)]`, summing to the 3 compared cases.
    - `UNSPECIFIED_ID: UNCHANGED` yields no row and counts under `unchanged`.
    - existing tests keep passing (only the fixture grew).
  - `test_judge_display.py`: a result with `PARTIAL_ID: UNCHANGED` prints the `partial:` legend line and `Cases: ... 1 partial`. The existing flip test asserts `partial:` is absent (one added assertion, or a separate test).
- **Verify**:
  - `uv run pytest tests/unit -n auto`: all green.
  - `uv run pytest tests/integration -n auto`: all green (Docker test may skip).
  - `uv run pyright`: 0 errors.
  - `uv run ruff check .` and `uv run ruff format --check .`: clean.
  - Live, optional and by hand: `uv run python -m evals.run_judge_eval` (needs `OPENAI_API_KEY`). A partial row appears only if the judge detects an always-missed case in some runs, so its absence proves nothing.
