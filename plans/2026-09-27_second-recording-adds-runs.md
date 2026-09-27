# A second honeypot recording adds its runs to the first

## Context

[ADR 023](../docs/adr/023-honeypot-second-recording.md), accepted in `5553493`, replaces the agreement test a second honeypot recording must pass to confirm the first. Today `evals/recording.py` confirms an exploratory baseline only if every cell whose observation was the same in all runs of the first recording keeps it in every run of the second (`_disagreements`), and the confirmed baseline then holds the second recording's runs alone (`_second_recording`). On a disagreement, the second recording becomes a new exploratory baseline, so the confirmation is retried until two recordings happen to agree.

Under ADR 023 the second recording adds its runs to the first: the confirmed baseline holds the runs of both, and a cell is stable only if every one of those runs gives it the same observation. The second recording is refused on the grounds that applied before, except that ADR 022's condition (a stable and correct planted FAIL cell and PASS cell) now reads the combined runs.

This is a change to the instrument, the recording code. It is alone in its commit with its labeling log entry (ADR 020). No label, observation, floor or metric formula moves.

## Decisions taken in discussion

- **`disagreements` stays.** It decides nothing any more. It stays in the baseline file and in the console as a diagnostic: the cells the first recording showed stable that varied in the second, the ones the combination took out of the gated set on evidence that the old rule would have treated as a failed confirmation.
- **The first-baseline gap is handled in the refusal message, not in ADR 023.** ADR 023 says a second recording refused on a floor or under ADR 022 is not made again against the same first recording, and the change that reset the baseline is reverted. For a first baseline there is no change to revert. The refusal message states both cases: after a reset, revert the change and discard both recordings; for a first baseline, ADR 023 decides nothing, and the way forward is decided before recording again. The code cannot tell the two cases apart (a baseline file has no memory of what preceded it), so the message carries both.
- **"Not made again" is carried by the message alone.** A refusal writes nothing, so the exploratory file stays and nothing in the code stops a second recording from being made again against it. The code does not delete or mark the file on these refusals. Like the rules of ADR 020, this one rests on review and the refusal message.

## Approach

1. `Recording` carries the ground truth its runs were scored under, so the recording code can classify the combined runs without a fourth argument to `decide_recording`.
2. A second recording over an exploratory baseline is combined with it first: runs concatenated (first recording's runs, then the second's), metrics and protected cells recomputed over the combined runs. Refusals read the combined protected cells for ADR 022, and the second recording's own gate for the floors. If nothing refuses, the result is a confirmed baseline holding the combined runs, with `confirms` pointing at the first recording and `disagreements` listing the cells that varied in the second after looking stable in the first.
3. `baseline_integrity` accepts a baseline that holds twice its claimed runs when it confirms a first recording, and only then.
4. Console text, living docs, CHANGELOG and a labeling log entry follow.

## Files to modify

### `evals/recording.py`

`Recording` gains one field:

```python
class Recording(BaseModel):
    conditions: BaselineConditions
    commit: str
    recorded_at: str
    runs: list[dict[Cell, Observation]]
    metrics: EvalMetrics
    completed_all: bool
    protected: ProtectedCells
    ground_truth: GroundTruth
```

`GroundTruth` is `dict[tuple[str, AuditCategory], EvalVerdict]`. Pydantic v2 validates tuple dict keys in Python mode, and `Recording` is never serialized. If pyright or pydantic objects, the fallback is `model_config = ConfigDict(arbitrary_types_allowed=True)`, not a change of the type.

`decide_recording` keeps its signature. Its body becomes:

```python
def decide_recording(
    existing: Baseline | None, recording: Recording, gate: GateResult
) -> Baseline | RecordingRefused:
    if existing is not None and existing.status == BaselineStatus.EXPLORATORY:
        return _second_recording(existing, recording, gate)
    reasons = _refusals(existing, recording, gate)
    if reasons:
        return RecordingRefused(reasons=reasons)
    if existing is None:
        return _baseline_from(recording, BaselineStatus.EXPLORATORY, ReplayRule())
    return _baseline_from(recording, BaselineStatus.CONFIRMED, existing.replay_rule).model_copy(
        update={"replaces": _ref(existing)}
    )
```

`_refusals` loses its exploratory branch: it covers a first recording and a recording over a confirmed baseline, as today.

`_second_recording` becomes the whole path over an exploratory baseline:

```python
def _second_recording(
    existing: Baseline, recording: Recording, gate: GateResult
) -> Baseline | RecordingRefused:
    combined = _combined(existing, recording)
    reasons = _second_recording_refusals(existing, combined, gate)
    if reasons:
        return RecordingRefused(reasons=reasons)
    return _baseline_from(combined, BaselineStatus.CONFIRMED, existing.replay_rule).model_copy(
        update={"confirms": _ref(existing), "disagreements": _disagreements(existing, recording)}
    )
```

`_second_recording_refusals(existing, combined, gate)` takes three arguments (CLAUDE.md: aim for three at most): `combined` is the second recording with only `runs`, `metrics` and `protected` replaced, so its `completed_all`, `commit` and `conditions` are the second recording's own. Its reasons, in this order:

1. `"a run failed: ..."` when `not combined.completed_all`, the message of today. This refusal alone lets the second recording be made again.
2. The floor breaches of `gate` (the second recording's own three runs), as today.
3. The blind sides of `combined.protected` (ADR 022 on the combined runs), with the wording of today's `_blind_sides` reasons and "over the runs of both recordings" added.
4. `exploratory_commit_refusal(existing, combined.commit)` and `condition_refusals(existing, combined.conditions)`, as today.

When reason 2 or 3 is present, one more reason is appended, `_NOT_MADE_AGAIN`:

```python
_NOT_MADE_AGAIN = (
    "this second recording is not made again against the same first recording (ADR 023). If a "
    "change reset the baseline, revert it and discard both recordings. For a first baseline, "
    "ADR 023 decides nothing: decide the way forward before recording again"
)
```

`_combined` builds the second recording with the first one's runs added:

```python
def _combined(existing: Baseline, recording: Recording) -> Recording:
    runs = existing.observation_runs() + recording.runs
    return recording.model_copy(
        update={
            "runs": runs,
            "metrics": _combined_metrics(existing, recording, runs),
            "protected": protected_cells(runs, recording.ground_truth),
        }
    )
```

`_combined_metrics` computes recall and precision with `label_scores` over the combined runs, consistency with `compute_consistency` over them, both under `recording.ground_truth`, and distribution coverage as the mean of the two recordings' values (both hold the same number of runs, and coverage cannot be recomputed from observations). The runs are turned into verdict maps the way `rescore` does it (`UNCOVERED` becomes `None`): extract that conversion from `rescore` into a public function of `evals/baseline.py`, `verdict_maps_of(runs: list[dict[Cell, Observation]]) -> list[VerdictMap]`, used by both.

`_disagreements` keeps its current body and meaning.

`_RESET_PROCEDURE` stays as is: "record twice at that commit (exploratory, then confirmed)" and "each must come out stable and correct in the confirmed baseline" still hold, the confirmed baseline now holding both recordings' runs.

### `evals/baseline.py`

- `verdict_maps_of`, extracted from `rescore` as above. `rescore` calls it.
- `baseline_integrity`: the expected number of runs is `conditions.runs * 2` when `baseline.confirms is not None`, and `conditions.runs` otherwise. The problem message names the reason: `f"the baseline holds {n} runs, its conditions and its confirmation claim {expected}"` when it confirms, the current message otherwise.
- `Baseline.disagreements`: no change of type. The comment above `protected` stays.

### `evals/run_evals.py`

`_record` passes `ground_truth=MERGED_GROUND_TRUTH` to `Recording`.

### `evals/fault_harness.py`

`_recording_refusals` passes `ground_truth=MERGED_GROUND_TRUTH` to `Recording`. Nothing else changes there: it records a first recording.

### `evals/eval_display.py`

In `print_written_recording`, the disagreement line reads `f"- looked stable in the first recording and varied in the second: {key}"`. The `leaves the gated set` lines already show what the combination removed, since `gated_set_changes` compares the exploratory baseline with the combined one.

### Tests

The recording tests leave `tests/unit/test_eval_baseline.py` (521 lines) for a new `tests/unit/test_eval_recording.py`: every test that calls `decide_recording` or `gated_set_changes`, moved unchanged except where this plan changes their expectation. The new test file gets its own given module, `tests/unit/support/test_eval_recording_given.py` (CLAUDE.md: one given/then pair per test file). The helpers only the recording tests use (`a_recording`, `a_gate`, `protected_on_both_sides`, `no_stable_and_correct_fail_cell`, `no_stable_and_correct_pass_cell`, and any of the `runs_where_*` helpers no remaining baseline test calls) move there. Those `test_eval_baseline.py` or `test_eval_session_given.py` still use (`a_baseline`, `conditions`, `all_correct_runs`, ...) stay in `test_eval_baseline_given.py` and are imported from it, as `test_eval_baseline_given.py` already imports from `test_eval_gate_given.py`. `a_recording` gains `ground_truth: GroundTruth | None = None`, defaulting to `a_ground_truth()`. `tests/unit/test_eval_fault_injection.py:164` passes `ground_truth=MERGED_GROUND_TRUTH` to `Recording`.

A second recording's own `protected` argument no longer decides anything: ADR 022 reads `protected_cells` of the combined runs under the recording's ground truth. The default `a_ground_truth()` has a single FAIL cell and a single PASS cell, so any second-recording test that makes one of them unstable is refused under ADR 022. Those tests use `a_ground_truth_with_two_cells_of_each_side()` (`tests/unit/support/test_eval_gate_given.py`), passed to both `a_baseline(ground_truth=...)` and `a_recording(ground_truth=...)`, with runs that observe all four cells (`classify` gives no state to a cell missing from a run, so a two-cell run leaves the other two out of the count). A runs helper for four cells all correct goes in `test_eval_recording_given.py` (the existing `runs_on_two_cells_of_each_side` of `test_eval_gate_given.py` makes two of the cells unstable or incorrect, so it does not fit).

Changed expectations:

- `test_a_second_recording_agreeing_on_stable_cells_confirms_the_first`: also asserts the confirmed baseline holds 6 runs, the first recording's three then the second's.
- `test_a_second_recording_disagreeing_on_a_stable_cell_stays_exploratory` becomes `test_a_second_recording_disagreeing_on_a_stable_cell_confirms_with_the_cell_unstable`: status confirmed, `confirms` set, `replaces` None, `disagreements == [cell_key(VULNERABLE_CELL)]`, and the vulnerable cell is unstable in `result.protected`. Under the two-cells-of-each-side ground truth, with the other FAIL cell stable and correct in both recordings, that reads `fail_stable_correct == 1`, `unstable == 1` (with the single-FAIL ground truth the recording would be refused under ADR 022, which is its own test below).
- `test_a_cell_unstable_in_the_exploratory_baseline_is_no_disagreement`: today its only FAIL cell is unstable in the first recording, so the combined runs leave no stable and correct FAIL cell and it would be refused under ADR 022. It becomes the first new test below (two-cells-of-each-side ground truth), not a separate test.
- `test_a_second_recording_seeing_uncovered_where_the_first_saw_fail_disagrees`: confirmed, with the safe cell in `disagreements`, and refused if that leaves no stable and correct PASS cell. As above, give the ground truth enough cells for the case the test names.

New tests (in `test_eval_recording.py` unless stated):

- A cell unstable in the first recording and stable in the second is unstable in the confirmed baseline, is not in `disagreements`, and does not enter the gated set (`gated_set_changes(existing, result, ...)` has it in neither list).
- A second recording whose combined runs leave no stable and correct planted FAIL cell is refused, while each recording alone had one: first `FAIL, FAIL, FAIL` then `PASS, PASS, PASS` on the only FAIL cell. The reasons name the planted FAIL cell and include the ADR 023 sentence.
- Same with no stable and correct PASS cell.
- A second recording breaching a floor on its own runs is refused, and the reasons include the ADR 023 sentence.
- A second recording with a failed run is refused without the ADR 023 sentence.
- The confirmed baseline's recall and precision are the per-run averages over the six runs, its distribution coverage the mean of the two recordings'.
- The confirmed baseline's `protected` counts are those of the combined runs.
- `baseline_integrity` (in `test_eval_baseline.py`): a baseline with `confirms` set and twice its claimed runs has no problem. With `confirms` set and the claimed runs only, it has one. With `confirms` unset and twice the claimed runs, it has one.
- `rescore` of a combined baseline under a revised label reads all six runs (`test_eval_baseline.py`).
- A confirmed combined baseline, compared against a three-run candidate with `compare`, flips a cell stable and correct across the six runs and reports inconclusive on a cell that varied only in the second recording. `compare` needs no change, so this pins the behavior (in `test_eval_recording.py` or `test_eval_gate.py`, wherever the given helpers fit).

Unchanged tests that must keep passing: a second recording at another commit or at other conditions is refused, and every test of recording over a confirmed baseline.

### `docs/labeling-log.md`

A new entry, `### 2026-09-27, second recording`, after the last one, in the shape of the entries of the same day:

- `Commit: the one that adds this entry.` as a plain line, as in the entries above it.
- **Ground truth.** Unchanged, 36 cells, 8 FAIL.
- **State of the gate.** No baseline is committed, so no gate compares against one and no reset applies. The exploratory baseline recorded at `d79e39d` was never committed and is deleted before the next recording.
- **What changes.** A second recording at the same commit confirms the first by adding its runs to it. The confirmed baseline holds the runs of both, and a cell is stable only if all of them give it the same observation. ADR 022's condition reads the combined runs. A second recording refused on a floor or under ADR 022 is not made again against the same first recording. No observation, label, floor or metric formula moves. See ADR 023.
- **The recordings that raised it.** At `d79e39d` on 2026-09-27, the second recording disagreed with the first on `execute_query × injection`, `list_items × input_validation` and `project_manager × info_leakage`, and under the rule then in force it replaced the first as a new exploratory baseline.
- **The four questions of ADR 016.** (1) The change lands in the instrument, the recording code. (2) It was noticed after the confirmation of 2026-09-27 disagreed, a measurement, which moves the burden to (3) and (4). (3) The target is a confirmation that ends, and gates only the cells stable over every run recorded at the commit. The criterion reads no measured value. (4) The rule applies to every cell of every second recording. On a pair of recordings that agree, it gates a subset of what the old rule gated: a cell that varied in the first recording and looked stable in the second was gated before, and is not now. On a pair that disagrees, it confirms where the old rule started over.

### `CONTRIBUTING.md`

Line 68: "A second recording at the same commit confirms it when it classifies the same cells as stable" becomes: a second recording at the same commit confirms it by adding its runs, the confirmed baseline holds the runs of both, and only a cell that every one of those runs observes the same way is gated. Add that a second recording refused on a floor, or for leaving no stable and correct cell on one side over the combined runs, is not made again against the same first recording (ADR 023), and that one refused for a failed run can be. Line 76 (the procedure) stays. Add ADR 023 to the links of the paragraph.

### `CHANGELOG.md`

In the `[Unreleased]` entry on the e2e evals gate, add one sentence after the recording refusal: a second recording at the same commit confirms the first by adding its runs, and a cell is gated only if every run of both gives it the same observation. Add ADR 023 to its links.

### `CLAUDE.md`, `README.md`

No change. `CLAUDE.md` line 13 ("run it twice at the same commit (exploratory, then confirmed)") still holds, and the README does not describe the confirmation.

## What stays unchanged

- `evals/gate.py`: `classify`, `compare`, `protected_cells`, the replay rule and the floors. They already take any number of runs.
- `evals/judging.py`: `rescore` and the deltas read whatever runs the baseline holds.
- The condition `runs`: still the number one recording makes, and a candidate runs at that count.
- Recording over a confirmed baseline: its runs replace the old ones and are not added (ADR 023, last consequence).
- A first recording: refused on the same grounds as today, on its own runs.
- `exploratory_commit_refusal`, `condition_refusals`, `rescore_refusals` and `gated_set_changes`.
- ADR 016, 020, 022 and 023, and every plan.

## Edge cases

| Case | Expected |
|---|---|
| Second recording agrees with the first on every stable cell | Confirmed, 6 runs, `disagreements` empty |
| A cell stable in the first, varying in the second | Confirmed, cell unstable, in `disagreements`, leaves the gated set |
| A cell varying in the first, stable in the second | Confirmed, cell unstable, not in `disagreements`, never gated |
| `FAIL` in the first, `UNCOVERED` in a run of the second | Same as a disagreement: unstable, listed |
| Second recording with a run that did not complete | Refused, no ADR 023 sentence, the exploratory file stays, a new second recording can be made |
| Second recording breaching a floor on its own runs | Refused, ADR 023 sentence |
| Combined runs leave no stable and correct FAIL or PASS cell | Refused, ADR 023 sentence |
| Second recording at another commit or other conditions | Refused as today |
| Confirmed baseline holding 6 runs loaded by the runner | No integrity problem |
| Baseline with `confirms` set and 3 runs, or without it and 6 | Integrity problem, refused before any LLM call |
| Label revision over a combined baseline | Re-scored over the 6 runs, ADR 022 read on them |
| Recording over a combined confirmed baseline, gate green | Replaces it with its own 3 runs, `replaces` set, `confirms` None |

## After the implementation (not a step of this plan)

1. Delete the untracked `evals/baselines/honeypot_e2e.json` recorded at `d79e39d`. The recording code would refuse it anyway, since it was recorded at another commit.
2. From a clean tree at the implementation commit, run `uv run python -m evals.run_evals --record-baseline` twice (about 12 minutes each).
3. Commit the confirmed baseline in a commit of its own.

## Verification

```bash
uv run pytest tests/unit -n auto
uv run pytest tests/integration -n auto
uv run ruff check .
uv run ruff format --check .
uv run pyright
```

The integration suite matters here because the fault injection harness builds a `Recording`.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites, read by later passes, the implementation-phase fact check included. A line here records what was concluded once, not what is true now: no pass may treat it as a reason to skip a verification. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `ground_truth: GroundTruth` as a `Recording` field, with `GroundTruth = dict[tuple[str, AuditCategory], EvalVerdict]`, validates and survives `model_copy(update=...)` under pydantic v2 in Python mode (verified by executing it against the installed pydantic 2.12 with `MERGED_GROUND_TRUTH`, 36 cells, 8 FAIL)

## Implementation steps

Verification commands (from `CLAUDE.md`): `uv run pytest tests/unit -n auto`, `uv run pytest tests/integration -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`.

The behavior change is an instrument change and must sit alone in its commit with its labeling log entry (ADR 020), so everything that changes what a recording decides lands in Step 2. Step 1 only prepares the ground and changes no outcome.

### Step 1: Recording carries its ground truth, `verdict_maps_of`, recording tests in their own file

- **Files**:
  - Create `tests/unit/support/test_eval_recording_given.py`, `tests/unit/test_eval_recording.py`
  - Modify `tests/unit/test_eval_baseline.py`, `tests/unit/support/test_eval_baseline_given.py`, `tests/unit/test_eval_fault_injection.py`
  - Modify `evals/recording.py`, `evals/baseline.py`, `evals/run_evals.py`, `evals/fault_harness.py`
- **Do**:
  1. Tests first, a pure move with no change of expectation:
     - Move every test of `tests/unit/test_eval_baseline.py` that calls `decide_recording` or `gated_set_changes` (from `test_a_first_recording_is_exploratory` to the end of the file) into the new `tests/unit/test_eval_recording.py`, unchanged. Drop the now unused imports from `test_eval_baseline.py` (`evals.recording`, `CellOutcome`, `GateMode`, `GateVerdict`, `RecordingRef`, ... whatever ruff flags).
     - Move the helpers only those tests use from `test_eval_baseline_given.py` into the new `tests/unit/support/test_eval_recording_given.py`: `a_recording`, `a_gate`, `protected_on_both_sides`, `no_stable_and_correct_fail_cell`, `no_stable_and_correct_pass_cell`, `runs_where_safe_cell_is`. Keep in `test_eval_baseline_given.py` what `test_eval_baseline.py` or `test_eval_session_given.py` still use (`RECORDED_COMMIT`, `conditions`, `a_baseline`, `all_correct_runs`, `runs_where_vulnerable_cell_is`, `ObservationRuns`, the re-exported `VULNERABLE_CELL`, `SAFE_CELL`, `a_ground_truth`). `test_eval_recording_given.py` imports those from `test_eval_baseline_given.py` (and gate helpers from `test_eval_gate_given.py`), and re-exports what the test file reads through `given.` so the test file keeps a single `import tests.unit.support.test_eval_recording_given as given`.
     - `a_recording` gains `ground_truth: GroundTruth | None = None`, passing `ground_truth=ground_truth or a_ground_truth()` to `Recording`.
     - `tests/unit/test_eval_fault_injection.py:164`: pass `ground_truth=MERGED_GROUND_TRUTH` to `Recording`.
  2. Production:
     - `evals/recording.py`: `Recording` gains `ground_truth: GroundTruth` (last field). No other change in this step, `decide_recording` behaves as today.
     - `evals/run_evals.py` `_record` and `evals/fault_harness.py` `_recording_refusals`: pass `ground_truth=MERGED_GROUND_TRUTH` (import it in `fault_harness.py` if it is not already).
     - `evals/baseline.py`: extract from `rescore` a public `verdict_maps_of(runs: list[dict[Cell, Observation]]) -> list[VerdictMap]` (`UNCOVERED` becomes `None`, any other observation `EvalVerdict(seen.value)`), placed right below `rescore` (newspaper rule), and make `rescore` call it.
- **Test**: no new scenario. Every moved test passes unchanged in `test_eval_recording.py`, the remaining ones in `test_eval_baseline.py`. Test count of the unit suite is unchanged.
- **Verify**: `uv run pytest tests/unit -n auto` green with the same number of tests as before, `uv run pytest tests/integration -n auto` green (the fault harness builds a `Recording`), `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright` clean. Commit as a refactor (`refactor(evals): ...`), no labeling log entry since no decision changes.

### Step 2: A second recording adds its runs to the first (ADR 023)

- **Files**:
  - Modify `tests/unit/test_eval_recording.py`, `tests/unit/support/test_eval_recording_given.py`, `tests/unit/test_eval_baseline.py`
  - Modify `evals/recording.py`, `evals/baseline.py`, `evals/eval_display.py`
  - Modify `docs/labeling-log.md`, `CONTRIBUTING.md`, `CHANGELOG.md`
- **Do**:
  1. Tests first (`test_eval_recording.py` and its given module unless stated), run them and see them fail:
     - Given helper: a runs helper observing the four cells of `a_ground_truth_with_two_cells_of_each_side()` all correct (FAIL on `VULNERABLE_CELL` and `OTHER_VULNERABLE_CELL`, PASS on `SAFE_CELL` and `OTHER_SAFE_CELL`, three runs), with a way to override one cell's observations per run (e.g. `four_cell_runs(vulnerable=(FAIL, PASS, FAIL))`). Tests using the four-cell ground truth pass it to both `a_baseline(ground_truth=...)` and `a_recording(ground_truth=...)`.
     - Rewrite the four changed expectations listed under "Changed expectations" in the Tests section above (6 runs on agreement, disagreement now confirms with the cell unstable, the old "unstable in the exploratory baseline" test folded into the first new test, uncovered-vs-fail now confirms and lists the safe cell, under a ground truth with enough cells).
     - Add the new tests listed under "New tests": varying-in-first-stable-in-second (unstable, not in `disagreements`, in neither list of `gated_set_changes`), combined runs leave no stable and correct FAIL cell (first `FAIL×3`, second `PASS×3` on the only FAIL cell, reasons name the planted FAIL cell and contain the `_NOT_MADE_AGAIN` sentence), same for the PASS side, floor breach on the second recording's own gate (ADR 023 sentence present), failed run (refused, ADR 023 sentence absent), combined metrics (recall and precision are per-run averages over six runs, distribution coverage the mean of the two recordings' values: give them different coverages), combined `protected` counts, and the `compare` pin (a confirmed combined baseline against a three-run candidate: a cell stable and correct over six runs that flips is reported as a flip, a cell that varied only in the second recording is inconclusive/not gated; read `evals/gate.py` `compare` for its exact outcome names).
     - In `test_eval_baseline.py`: `baseline_integrity` with `confirms` set and six runs has no problem, with `confirms` set and three runs names the confirmation message, with `confirms` unset and six runs names the current message. Set `confirms` with `model_copy(update={"confirms": RecordingRef(...)})` on `given.a_baseline(...)`, six runs as `given.all_correct_runs() + given.all_correct_runs()`. Plus `rescore` of a six-run baseline under a revised label reads all six runs (e.g. make one run of the second three disagree, and check recall reflects it).
  2. Production, `evals/recording.py`: implement `decide_recording`, `_second_recording`, `_second_recording_refusals`, `_combined`, `_combined_metrics` and `_NOT_MADE_AGAIN` exactly as the "Files to modify" section specifies (refusal order: failed run, floors of `gate`, blind sides of the combined `protected` with "over the runs of both recordings" in the wording, commit and condition refusals, then `_NOT_MADE_AGAIN` appended only when a floor or blind-side reason is present). `_refusals` loses its exploratory branch. `_combined_metrics` uses `label_scores` and `compute_consistency` over `verdict_maps_of(runs)` under `recording.ground_truth`, and averages the two distribution coverages. `_disagreements` and `_RESET_PROCEDURE` unchanged. Keep functions under ~20 lines and the file under ~300 lines. Public functions above their private helpers.
  3. `evals/baseline.py` `baseline_integrity`: expected runs `conditions.runs * 2` when `baseline.confirms is not None`, message `f"the baseline holds {n} runs, its conditions and its confirmation claim {expected}"` in that case, current message otherwise. Keep it within ~20 lines (extract a small helper for the run-count problem if needed).
  4. `evals/eval_display.py` `print_written_recording`: the disagreement line becomes `f"- looked stable in the first recording and varied in the second: {key}"`.
  5. Docs, as specified in the plan: the `### 2026-09-27, second recording` entry in `docs/labeling-log.md` after the last entry, in the shape of the same-day entries (commit line, ground truth, state of the gate, what changes, the recordings that raised it, ADR 016's four questions), the `CONTRIBUTING.md` paragraph at line 68 (plus ADR 023 link), the one sentence and ADR 023 link in the `[Unreleased]` e2e evals gate entry of `CHANGELOG.md`. No change to `CLAUDE.md`, `README.md`, ADRs or plans. User writing preferences apply: no em dashes, avoid semicolons.
- **Test**: the scenarios above, expected results as in the plan's edge-case table. Unchanged tests (second recording at another commit or conditions refused, all recording over a confirmed baseline, first recording) keep passing.
- **Verify**: `uv run pytest tests/unit -n auto`, `uv run pytest tests/integration -n auto`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, all green. One commit holding the code, tests and the labeling log entry, nothing else (ADR 020). No plan-phase references in the commit message.
