# Split the conclusion check: the rule apart from the computation

## Context

The unit short loop (`uv run pytest tests/unit -n auto --maxprocesses 4`) takes about 17 s. About 6 s of it are four tests: `test_check_conclusion_agrees_when_every_method_places_the_gap_above_zero` and `test_check_conclusion_is_inconclusive_when_...` in `tests/unit/test_holdout_statistic.py` and `tests/unit/test_nuisance_statistic.py`, about 3.2 s each. Each calls `check_conclusion`, which computes eight intervals, four of them `contrast_hierarchical` on the production grid (about 0.75 s a call), and then applies a cheap rule: the conclusion is inconclusive when any method places the gap differently from the cited one.

The tests are about the rule but pay for the computation. The code shows two more signals of the same design problem:

- `check_conclusion` and its method list are duplicated verbatim in `evals/holdout_statistic.py` and `evals/nuisance_statistic.py`. The two copies differ only in how each side is counted (the holdout's observed and "unchecked as misses" readings, the nuisance suite's observed split and "incomplete as flagged" readings).
- The cited method is encoded by list position (`placements[0]`), and each side's counts are six loose local variables per module, so a method fed the wrong list is the bug these tests could catch, at 3 s each.

The numerical grid is not the missing concept: it is the resolution of one method's integral, already a `Grid` value object in `evals/holdout_hierarchical.py`, whose accuracy is pinned by `tests/unit/test_holdout_hierarchical.py`. Passing a grid through `check_conclusion`, or monkeypatching `contrast_hierarchical` in the tests, were both considered and rejected: the first puts a solution-space knob in a domain signature with one production value, the second couples the tests to how the modules import the function.

A separate, unrelated cost of about 0.35 s per xdist worker is the `langsmith_plugin` pytest plugin, loaded by the `langsmith` dependency and used by no test.

## Approach

1. Extract the rule into one shared pure function, `conclude(cited, others)`, used by both modules. Test it exhaustively on hand-built placements.
2. Name the way a side is counted: a `Reading` value object (the share sum and the runs counted per target or server) and one shared `read_contrast(reading_a, reading_b, runs, suffix)` that applies the four methods to a pair of readings. Each module then only states how it builds its readings, which is pure data and tested directly. `check_conclusion` keeps its signature and its behaviour.
3. Disable the unused langsmith pytest plugin in `addopts`.

The production grid, the method set, the method names and every published number stay as they are. Every verdict `check_conclusion` returns must be identical, bit for bit, before and after.

## Files

### `evals/holdout_statistic.py`

Add `Reading` beside the other value objects (after `MethodPlacement`), and the new functions below `check_conclusion`, each caller above its helpers per the newspaper rule (CLAUDE.md): `check_conclusion`, then `conclude`, `read_contrast`, `observed`, `unchecked_as_misses`, then the existing `placed` (already shared with the nuisance module):

```python
@dataclass(frozen=True)
class Reading:
    """One way of counting a side: the sum of its shares, and the runs counted per member."""

    share_sum: float
    counted_runs: tuple[int, ...]

    @property
    def members(self) -> int:
        return len(self.counted_runs)


def conclude(cited: MethodPlacement, others: Sequence[MethodPlacement]) -> ConclusionVerdict: ...


def read_contrast(
    reading_a: Reading, reading_b: Reading, runs: int, suffix: str = ""
) -> list[MethodPlacement]:
    """Newcombe, Agresti-Caffo and the two hierarchical contrasts, in that order, each named
    with the suffix appended."""
```

`conclude` holds today's rule verbatim: `disagreeing = tuple(m for m in others if m.placement is not cited.placement)`, then the two `ConclusionVerdict` returns.

`read_contrast` returns, in this order, `newcombe{suffix}`, `agresti_caffo{suffix}`, `hierarchical_gamma_1_1{suffix}`, `hierarchical_gamma_2_2{suffix}`, calling `newcombe(reading_a.share_sum, reading_a.members, reading_b.share_sum, reading_b.members)`, `agresti_caffo` with the same arguments, and `contrast_hierarchical(reading_a.counted_runs, reading_b.counted_runs, runs, prior)` for `_GAMMA_1_1` then `_GAMMA_2_2`. The method names and their order are exactly today's, so reports and stored results read the same.

`check_conclusion(side_a, side_b, runs)` keeps its signature and its `_MIN_SIDE` guard, then:

```python
cited, *others = [
    *read_contrast(observed(side_a), observed(side_b), runs),
    *read_contrast(
        unchecked_as_misses(side_a, runs), unchecked_as_misses(side_b, runs), runs, "_unchecked"
    ),
]
return conclude(cited, others)
```

The holdout readings, public and placed below `read_contrast`:

- `observed(side: SideStatistic) -> Reading`: `Reading(side.share_sum, tuple(r.detected_runs for r in side.results))`.
- `unchecked_as_misses(side: SideStatistic, runs: int) -> Reading`: `Reading(_unchecked_sum(side.results, runs), tuple(r.detected_runs_if_unchecked_missed for r in side.results))`.

Each `share_sum` is computed by the same expression as today (`side.share_sum`, `_unchecked_sum`), so the floats are identical. `contrast_hierarchical` takes `Sequence[int]`, so a tuple in place of today's list changes nothing it computes (it counts the values in input order either way).

Delete `_conclusion_methods` and `_hier_contrast` (its only caller). `_hierarchical` stays (used by `primary_controls`).

### `evals/nuisance_statistic.py`

`check_conclusion(side_a, side_b, runs)` keeps its signature and guard (`side.servers < _MIN_SIDE`) and becomes the same three-line composition, with its own readings and the suffix `"_incomplete_as_flagged"`. It imports `Reading`, `read_contrast` and `conclude` from `evals.holdout_statistic`.

The nuisance readings, public and placed right below `check_conclusion`:

- `observed(side: SideStatistic) -> Reading`: `Reading(side.split_share_sum, tuple(r.split_flagged_runs for r in side.results))`.
- `incomplete_as_flagged(side: SideStatistic, runs: int) -> Reading`: `Reading(_split_incomplete_as_flagged_sum(side.results, runs), tuple(r.split_flagged_runs + r.incomplete_unflagged_runs for r in side.results))`.

Delete `_conclusion_methods`. Drop the imports that become unused: `agresti_caffo`, `contrast_hierarchical`, `placed` and `MethodPlacement`. `newcombe` stays (used by `contrast`), and so do `GammaPrior`, `hierarchical_interval` and the two `_GAMMA_*` constants (used by `primary_controls`).

### `pyproject.toml`

`addopts = "--dist worksteal -p no:langsmith_plugin"`, with one comment line saying the plugin comes with the langsmith dependency, no test uses it, and it costs each xdist worker about a third of a second to load.

### Tests

`tests/unit/test_holdout_statistic.py`:

- Delete `test_check_conclusion_agrees_when_every_method_places_the_gap_above_zero` and `test_check_conclusion_is_inconclusive_when_unchecked_as_misses_moves_the_placement`, and `_lopsided_sides` if nothing else uses it.
- Keep `test_check_conclusion_is_none_below_five_targets_a_side` (it returns before any computation).
- Add the rule tests, on hand-built `MethodPlacement`s (`placed("newcombe", Interval(0.10, 0.60))` and so on, no computation):
  - every method agrees above zero: the verdict carries `Placement.ABOVE`, `inconclusive` false, the cited method, no disagreeing method.
  - every method agrees below zero, and every method straddles: the agreed placement is carried (`BELOW`, `STRADDLES`).
  - one other method places the gap differently: `ConclusionVerdict(None, True, cited, (moved,))`.
  - several disagree: all of them are listed, in input order, and the agreeing ones are not.
  - no other method: the cited placement stands.
- Add the reading tests: `observed` of a side gives its share sum and its detected runs per target, `unchecked_as_misses` gives `_unchecked_sum`'s value and each target's `detected_runs_if_unchecked_missed`.
- Add one panel test, the only one on the production grid, about 1.5 s (two hierarchical calls): `read_contrast` on a pair of lopsided readings (`Reading(5.0, (3,) * 5)` against `Reading(0.0, (0,) * 5)`, `runs=3`, the counts of the deleted agreeing test, where all eight methods placed the gap above zero) returns the four method names, in order, with the suffix appended, each placed `ABOVE`. This is the guard on which methods make up the conclusion check, kept on purpose at its honest cost.

`tests/unit/test_nuisance_statistic.py`:

- Delete the two slow `check_conclusion` tests. Keep `test_check_conclusion_is_none_below_five_servers_a_side`.
- Add the reading tests: `observed` counts only the runs flagged through the split flaw (`split_share_sum`, `split_flagged_runs`), `incomplete_as_flagged` adds each server's incomplete unflagged runs to its split flagged runs, in the sum and per server.

No committed test runs `check_conclusion` past its guard any more, so which reading feeds the cited panel and which the sensitivity panel (and the nuisance suffix) is guarded by the equality check below, not by the suite. Accepted: the composition is three lines, and a test of it would pay the production grid four times again.

Given/then extraction only where a helper abstracts something (the existing `_sides`, `_result` and `a_server_result` builders are reused).

## What stays unchanged

- `evals/holdout_hierarchical.py` (no memoization, no grid change), `evals/holdout_intervals.py`.
- `check_conclusion`'s signature in both modules, its callers (`evals/holdout_report.py`, `evals/nuisance_report.py`), `ConclusionVerdict`, `MethodPlacement`, `placed`, `placement_of`.
- Every method name, their order, the cited method (Newcombe on the observed reading), the `_MIN_SIDE` guards, `contrast`, `primary_controls`, the published numbers.
- `tests/unit/test_holdout_hierarchical.py` and the report tests.

## Edge cases

- A side below `_MIN_SIDE`: `None`, before any reading is built (unchanged).
- `conclude` with no other method: the cited placement stands, `inconclusive` false.
- A `Reading` whose members differ between the two sides is allowed (the methods already take per-side counts).
- The holdout's cited placement and the sensitivity readings coincide when no run is unchecked: the computation still runs both, as today (no memoization in this change).

## Equality check (done once by the implementer, not committed)

Before the refactoring, record `check_conclusion`'s verdict for a set of side pairs in both modules: the four removed tests' inputs, a straddling case, a below-zero case, sides of unequal size, and a case with unchecked or incomplete runs on both sides. Record each verdict field by field with every interval bound as `float.hex`. After the refactoring, the same inputs must give the identical record. Run it with a throwaway script outside the repository, not a committed test (it would pay the production grid again).

## Verification

Test-first (CLAUDE.md, Workflow): write the rule, reading and panel tests before the extraction and run them to see them fail (the names do not exist yet), then extract.

```bash
uv run pytest tests/unit/test_holdout_statistic.py tests/unit/test_nuisance_statistic.py tests/unit/test_holdout_hierarchical.py -n 0 --durations=5
uv run pytest -n auto
uv run ruff check .
uv run ruff format .
uv run pyright
uv run pytest tests/unit -n auto --maxprocesses 4   # measure twice, expected about 11 s from about 17 s
```

## Docs

No command, flag or user-facing behaviour changes, so no living doc changes. Neither `CONTRIBUTING.md` nor `CLAUDE.md` describes the pytest `addopts` (checked), so the `pyproject.toml` comment is the only documentation of the plugin switch.

## Due diligence record

What the due-diligence pass concluded about the external facts this plan cites or defers, read by the later passes. A line here records what was concluded once, not what is true now: no pass may treat it as a reason to skip a verification. A human who edits the corresponding fact by hand deletes the line rather than updating it.

- SETTLED: `-p no:langsmith_plugin` (verified against the installed langsmith 0.14.12 `entry_points.txt`, `[pytest11] langsmith_plugin = langsmith.pytest_plugin`, and against `pytest --trace-config`, which lists `langsmith.pytest_plugin` without the flag and nothing langsmith with it)

## Implementation steps

### Step 1: Extract the conclusion rule and the readings, disable the langsmith plugin

**Files**:
- `tests/unit/test_holdout_statistic.py` (modify)
- `tests/unit/test_nuisance_statistic.py` (modify)
- `evals/holdout_statistic.py` (modify)
- `evals/nuisance_statistic.py` (modify)
- `pyproject.toml` (modify)
- a throwaway equality script outside the repository (not committed)

**Do**:
1. Equality baseline first, before touching any production code. Write a throwaway script outside the repository that builds side pairs for both modules (the four removed tests' inputs, a straddling case, a below-zero case, sides of unequal size, a case with unchecked or incomplete runs on both sides), calls each module's `check_conclusion`, and dumps every verdict field by field with each interval bound as `float.hex` to a file outside the repository. Run it and keep the output.
2. Tests, before the extraction (see "Tests" in the plan):
   - `tests/unit/test_holdout_statistic.py`: delete `test_check_conclusion_agrees_when_every_method_places_the_gap_above_zero`, `test_check_conclusion_is_inconclusive_when_unchecked_as_misses_moves_the_placement` and `_lopsided_sides` (no other user). Keep `test_check_conclusion_is_none_below_five_targets_a_side`. Add the `conclude` rule tests on hand-built `placed(...)` values, the `observed` / `unchecked_as_misses` reading tests (reusing `_result` and `split_by_side`), and the one `read_contrast` panel test on `Reading(5.0, (3,) * 5)` against `Reading(0.0, (0,) * 5)`, `runs=3`, with a non-empty suffix.
   - `tests/unit/test_nuisance_statistic.py`: delete the two slow `check_conclusion` tests, keep `test_check_conclusion_is_none_below_five_servers_a_side`, add the `observed` / `incomplete_as_flagged` reading tests (reusing `_sides` / `a_server_result`).
   - Run them and confirm they fail (import errors on the new names).
3. `evals/holdout_statistic.py`: add the frozen `Reading` dataclass after `MethodPlacement` (`share_sum: float`, `counted_runs: tuple[int, ...]`, `members` property). Below `check_conclusion`, in this order: `conclude(cited, others) -> ConclusionVerdict` (today's rule verbatim), `read_contrast(reading_a, reading_b, runs, suffix="") -> list[MethodPlacement]` (newcombe, agresti_caffo, hierarchical_gamma_1_1, hierarchical_gamma_2_2, each name + suffix, `contrast_hierarchical(reading_a.counted_runs, reading_b.counted_runs, runs, prior)` for the two priors), `observed(side)`, `unchecked_as_misses(side, runs)`, then the existing `placed`. Rewrite `check_conclusion`'s body as the guard plus the `cited, *others = [...]` composition of the plan. Delete `_conclusion_methods` and `_hier_contrast`, keep `_hierarchical`.
4. `evals/nuisance_statistic.py`: same composition with suffix `"_incomplete_as_flagged"`, readings `observed(side)` (`split_share_sum`, `split_flagged_runs`) and `incomplete_as_flagged(side, runs)` (`_split_incomplete_as_flagged_sum`, `split_flagged_runs + incomplete_unflagged_runs`) right below `check_conclusion`. Import `Reading`, `read_contrast`, `conclude` from `evals.holdout_statistic`. Delete `_conclusion_methods`, drop the now-unused imports (`agresti_caffo`, `contrast_hierarchical`, `placed`, `MethodPlacement`), keep `newcombe`, `GammaPrior`, `hierarchical_interval` and the `_GAMMA_*` constants. Check the method names the old `_conclusion_methods` produced match `name + "_incomplete_as_flagged"` exactly before deleting it.
5. `pyproject.toml`: `addopts = "--dist worksteal -p no:langsmith_plugin"` with a one-line comment (plugin shipped by the langsmith dependency, no test uses it, about a third of a second per xdist worker).
6. Rerun the equality script and diff its output against step 1's: it must be identical.

**Test**:
- `conclude`: all agree ABOVE gives `ConclusionVerdict(Placement.ABOVE, False, cited, ())`; all agree BELOW and all STRADDLES carry that placement; one other moved gives `ConclusionVerdict(None, True, cited, (moved,))`; several disagree lists them all in input order and omits the agreeing ones; no other method lets the cited placement stand.
- Holdout readings: `observed` gives the side's `share_sum` and per-target `detected_runs`; `unchecked_as_misses` gives `_unchecked_sum`'s value and per-target `detected_runs_if_unchecked_missed`.
- Nuisance readings: `observed` gives `split_share_sum` and per-server `split_flagged_runs`; `incomplete_as_flagged` adds each server's `incomplete_unflagged_runs` to its split flagged runs, in the sum and per server.
- Panel: `read_contrast` on the lopsided pair returns the four method names in order with the suffix appended, each placed `ABOVE` (about 1.5 s, the only test on the production grid).
- The two `_MIN_SIDE` guard tests stay green.

**Verify**:
- `uv run pytest tests/unit/test_holdout_statistic.py tests/unit/test_nuisance_statistic.py tests/unit/test_holdout_hierarchical.py -n 0 --durations=5`: green, the panel test the only one above a second.
- Equality script output identical before and after.
- `uv run pytest -n auto`, `uv run ruff check .`, `uv run ruff format .`, `uv run pyright` (no file argument): all green.
- `uv run pytest tests/unit -n auto --maxprocesses 4` measured twice: about 11 s, down from about 17 s.
