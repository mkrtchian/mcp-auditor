from pydantic import BaseModel

from evals.baseline import (
    Baseline,
    BaselineConditions,
    BaselineStatus,
    RecordedBaseline,
    RecordingRef,
    condition_mismatches,
    rescore,
    verdict_maps_of,
)
from evals.gate import (
    CellOutcome,
    CellState,
    Observation,
    ProtectedCells,
    RetestRule,
    classify,
    protected_cells,
)
from evals.gate_outcome import GateOutcome, GateResult
from evals.ground_truth import Cell, GroundTruth, cell_key
from evals.metrics import HoneypotMetrics, compute_consistency, label_scores

_RESET_PROCEDURE = (
    "reset the baseline under ADR 020: delete its file in the commit that makes the change, "
    "with no other change in that commit, and record twice at that commit (unconfirmed, then "
    "confirmed). If the gate was red, name the cells whose flip fired it at the last run, in "
    "the labeling log entry or, for a model, in the commit message: each must come out stable "
    "and correct in the confirmed baseline, or the change is reverted. It is reverted too when "
    "the recording is refused for leaving no planted FAIL cell or no PASS cell stable and "
    "correct (ADR 022). Runs and budget change only from a green gate. For a model, also run "
    "both models and record the delta while the old one answers (ADR 016)"
)

NOT_MADE_AGAIN = (
    "this second recording is not made again against the same first recording (ADR 023). If a "
    "change reset the baseline, revert it and discard both recordings. For a first baseline, "
    "ADR 023 decides nothing: decide the way forward before recording again"
)

_FAILED_RUN = "a run failed: a baseline must hold every run its conditions claim"

_FAIL_SIDE, _PASS_SIDE = "planted FAIL cell", "PASS cell"

FLIPPED_OUTCOMES = frozenset(
    {CellOutcome.FLIP, CellOutcome.REGRESSION, CellOutcome.FLIP_NOT_REPRODUCED}
)


class Recording(BaseModel):
    conditions: BaselineConditions
    commit: str
    recorded_at: str
    runs: list[dict[Cell, Observation]]
    metrics: HoneypotMetrics
    completed_all: bool
    ground_truth: GroundTruth

    @property
    def protected(self) -> ProtectedCells:
        return protected_cells(self.runs, self.ground_truth)


class RecordingRefused(BaseModel):
    reasons: list[str]


class GatedSetChange(BaseModel):
    entering: list[str]
    leaving: list[str]


def decide_recording(
    existing: Baseline | None, recording: Recording, gate: GateResult
) -> Baseline | RecordingRefused:
    if existing is not None and existing.status == BaselineStatus.UNCONFIRMED:
        return _second_recording(existing, recording, gate)
    reasons = _refusals(existing, recording, gate)
    if reasons:
        return RecordingRefused(reasons=reasons)
    if existing is None:
        return _baseline_from(recording, BaselineStatus.UNCONFIRMED, RetestRule())
    return _baseline_from(recording, BaselineStatus.CONFIRMED, existing.retest_rule).model_copy(
        update={"replaces": RecordingRef.of(existing)}
    )


def _refusals(existing: Baseline | None, recording: Recording, gate: GateResult) -> list[str]:
    reasons: list[str] = []
    if not recording.completed_all:
        reasons.append(_FAILED_RUN)
    reasons += [f"{name} under its floor" for name in gate.floor_breaches]
    reasons += [
        f"no {side} is stable and correct: the gate could not see {miss}"
        for side, miss in blind_sides(recording.protected, _FAIL_SIDE, _PASS_SIDE)
    ]
    if existing is None:
        return reasons
    return reasons + _confirmed_refusals(existing, recording, gate)


def rescore_refusals(baseline: Baseline, ground_truth: GroundTruth) -> list[str]:
    """A label revision re-scores the baseline (ADR 020). One that leaves a side with no stable
    and correct cell leaves the gate blind on that side, and a confirmed gate that cannot turn
    green cannot be recorded over: the baseline is reset (ADR 022).
    """
    protected = rescore(baseline, ground_truth).protected
    return [
        f"under the current labels the baseline holds no stable and correct {side}: delete the "
        f"baseline file in a commit of its own and record twice at that commit (ADR 022)"
        for side, _ in blind_sides(protected, _FAIL_SIDE, _PASS_SIDE)
    ]


def blind_sides(protected: ProtectedCells, fail_side: str, pass_side: str) -> list[tuple[str, str]]:
    """Each side with no stable and correct key, named, with the miss the gate could not see
    there (ADR 022)."""
    sides: list[tuple[str, str]] = []
    if protected.fail_stable_correct == 0:
        sides.append((fail_side, "a lost detection"))
    if protected.pass_stable_correct == 0:
        sides.append((pass_side, "a new false positive"))
    return sides


def _confirmed_refusals(existing: Baseline, recording: Recording, gate: GateResult) -> list[str]:
    reasons = condition_refusals(existing, recording.conditions)
    if gate.outcome != GateOutcome.GREEN:
        reasons.append(f"the gate is {gate.outcome}")
    reasons += [
        f"gated cell {key} flipped in this run ({comparison.outcome})"
        for key, comparison in gate.cells.items()
        if comparison.outcome in FLIPPED_OUTCOMES
    ]
    return reasons


def condition_refusals(baseline: Baseline, candidate: BaselineConditions) -> list[str]:
    mismatches = condition_mismatches(baseline.conditions, candidate)
    return conditions_differ_refusal(baseline, mismatches, _RESET_PROCEDURE)


def conditions_differ_refusal(
    baseline: RecordedBaseline, mismatches: list[str], reset_procedure: str
) -> list[str]:
    if not mismatches:
        return []
    return [
        f"conditions differ from the {baseline.status} baseline ({'; '.join(mismatches)}): "
        f"to run at other conditions without changing the baseline, pass --no-baseline. To change "
        f"the baseline's conditions, {reset_procedure}"
    ]


def _second_recording(
    existing: Baseline, recording: Recording, gate: GateResult
) -> Baseline | RecordingRefused:
    """The second recording adds its runs to the first, and a cell is stable only if every run
    of both gives it the same observation (ADR 023)."""
    combined = _combined(existing, recording)
    reasons = _second_recording_refusals(existing, combined, gate)
    if reasons:
        return RecordingRefused(reasons=reasons)
    stable_then_varying = disagreements(existing.observation_runs(), recording.runs)
    return _baseline_from(combined, BaselineStatus.CONFIRMED, existing.retest_rule).model_copy(
        update={
            "confirms": RecordingRef.of(existing),
            "disagreements": sorted(cell_key(cell) for cell in stable_then_varying),
        }
    )


def _combined(existing: Baseline, recording: Recording) -> Recording:
    runs = existing.observation_runs() + recording.runs
    return recording.model_copy(
        update={
            "runs": runs,
            "metrics": _combined_metrics(existing, recording, runs),
        }
    )


def _combined_metrics(
    existing: Baseline, recording: Recording, runs: list[dict[Cell, Observation]]
) -> HoneypotMetrics:
    # Coverage cannot be recomputed from observations. Both recordings hold the same number
    # of runs, so the mean of theirs is the mean over the combined runs.
    verdict_maps = verdict_maps_of(runs)
    consistency, _ = compute_consistency(verdict_maps, recording.ground_truth)
    coverage = (
        existing.metrics.distribution_coverage + recording.metrics.distribution_coverage
    ) / 2
    return HoneypotMetrics(
        **label_scores(verdict_maps, recording.ground_truth),
        consistency=consistency,
        distribution_coverage=coverage,
    )


def _second_recording_refusals(
    existing: Baseline, combined: Recording, gate: GateResult
) -> list[str]:
    """`combined` holds the runs of both recordings, and the second's own commit, conditions and
    completion. The floors read the second recording's own runs, through `gate`."""
    failed_run = [] if combined.completed_all else [_FAILED_RUN]
    not_made_again = [f"{name} under its floor" for name in gate.floor_breaches] + [
        f"no {side} is stable and correct over the runs of both recordings: the gate could not "
        f"see {miss}"
        for side, miss in blind_sides(combined.protected, _FAIL_SIDE, _PASS_SIDE)
    ]
    return (
        failed_run
        + not_made_again
        + unconfirmed_commit_refusal(existing, combined.commit)
        + condition_refusals(existing, combined.conditions)
        + ([NOT_MADE_AGAIN] if not_made_again else [])
    )


def unconfirmed_commit_refusal(baseline: RecordedBaseline, commit: str) -> list[str]:
    """A baseline is confirmed at the commit of its first recording. A change that lands while
    it is unconfirmed, a label revision included, resets it: the file is deleted and recorded
    again twice at the new commit.
    """
    if baseline.status != BaselineStatus.UNCONFIRMED or baseline.commit == commit:
        return []
    return [
        f"the unconfirmed baseline was recorded at {baseline.commit}, this run at "
        f"{commit}: confirm it at its own commit, or delete it in a commit of its own"
    ]


def disagreements[K](
    first_runs: list[dict[K, Observation]], second_runs: list[dict[K, Observation]]
) -> list[K]:
    """The keys stable over the first recording's runs that a run of the second sees otherwise
    (ADR 023)."""
    return [
        key
        for key, seen in first_runs[0].items()
        if all(run[key] == seen for run in first_runs)
        and any(run.get(key) != seen for run in second_runs)
    ]


def _baseline_from(recording: Recording, status: BaselineStatus, rule: RetestRule) -> Baseline:
    return Baseline(
        status=status,
        conditions=recording.conditions,
        retest_rule=rule,
        commit=recording.commit,
        recorded_at=recording.recorded_at,
        runs=[{cell_key(cell): obs for cell, obs in run.items()} for run in recording.runs],
        metrics=recording.metrics,
        protected=recording.protected,
    )


def gated_set_changes(
    old: Baseline | None, new: Baseline, ground_truth: GroundTruth
) -> GatedSetChange:
    before = _gated_set(old, ground_truth) if old else set[str]()
    after = _gated_set(new, ground_truth)
    return GatedSetChange(entering=sorted(after - before), leaving=sorted(before - after))


def _gated_set(baseline: Baseline, ground_truth: GroundTruth) -> set[str]:
    states = classify(baseline.observation_runs(), ground_truth)
    return {cell_key(cell) for cell, state in states.items() if state == CellState.STABLE_CORRECT}
