from pydantic import BaseModel

from evals.baseline import (
    Baseline,
    BaselineConditions,
    BaselineStatus,
    RecordingRef,
    condition_mismatches,
    rescore,
)
from evals.gate import (
    Cell,
    CellOutcome,
    CellState,
    Observation,
    ProtectedCells,
    ReplayRule,
    cell_key,
    classify,
    protected_cells,
)
from evals.gate_verdict import GateResult, GateVerdict
from evals.ground_truth import GroundTruth
from evals.metrics import EvalMetrics

_RESET_PROCEDURE = (
    "reset the baseline under ADR 020: delete its file in the commit that makes the change, "
    "with no other change in that commit, and record twice at that commit (exploratory, then "
    "confirmed). If the gate was red, name the cells whose flip fired it at the last run, in "
    "the labeling log entry or, for a model, in the commit message: each must come out stable "
    "and correct in the confirmed baseline, or the change is reverted. It is reverted too when "
    "the recording is refused for leaving no planted FAIL cell or no PASS cell stable and "
    "correct (ADR 022). Runs and budget change only from a green gate. For a model, also run "
    "both models and record the delta while the old one answers (ADR 016)"
)

_FLIPPED = {CellOutcome.FLIP, CellOutcome.REGRESSION, CellOutcome.FLIP_NOT_REPRODUCED}


class Recording(BaseModel):
    conditions: BaselineConditions
    commit: str
    recorded_at: str
    runs: list[dict[Cell, Observation]]
    metrics: EvalMetrics
    completed_all: bool
    protected: ProtectedCells


class RecordingRefused(BaseModel):
    reasons: list[str]


class GatedSetChange(BaseModel):
    entering: list[str]
    leaving: list[str]


def decide_recording(
    existing: Baseline | None, recording: Recording, gate: GateResult
) -> Baseline | RecordingRefused:
    reasons = _refusals(existing, recording, gate)
    if reasons:
        return RecordingRefused(reasons=reasons)
    if existing is None:
        return _baseline_from(recording, BaselineStatus.EXPLORATORY, ReplayRule())
    if existing.status == BaselineStatus.CONFIRMED:
        return _baseline_from(recording, BaselineStatus.CONFIRMED, existing.replay_rule).model_copy(
            update={"replaces": _ref(existing)}
        )
    return _second_recording(existing, recording)


def _refusals(existing: Baseline | None, recording: Recording, gate: GateResult) -> list[str]:
    reasons: list[str] = []
    if not recording.completed_all:
        reasons.append("a run failed: a baseline must hold every run its conditions claim")
    reasons += [f"{name} under its floor" for name in gate.floor_breaches]
    reasons += [
        f"no {side} is stable and correct: the gate could not see {miss}"
        for side, miss in _blind_sides(recording.protected)
    ]
    if existing is None:
        return reasons
    if existing.status == BaselineStatus.EXPLORATORY:
        return (
            reasons
            + exploratory_commit_refusal(existing, recording.commit)
            + condition_refusals(existing, recording.conditions)
        )
    return reasons + _confirmed_refusals(existing, recording, gate)


def rescore_refusals(baseline: Baseline, ground_truth: GroundTruth) -> list[str]:
    """A label revision re-scores the baseline (ADR 020). One that leaves a side with no stable
    and correct cell leaves the gate blind on that side, and a confirmed gate that cannot turn
    green cannot be recorded over: the baseline is reset (ADR 022).
    """
    rescored = rescore(baseline, ground_truth)
    protected = protected_cells(baseline.observation_runs(), rescored.ground_truth)
    return [
        f"under the current labels the baseline holds no stable and correct {side}: delete the "
        f"baseline file in a commit of its own and record twice at that commit (ADR 022)"
        for side, _ in _blind_sides(protected)
    ]


def _blind_sides(protected: ProtectedCells) -> list[tuple[str, str]]:
    sides: list[tuple[str, str]] = []
    if protected.fail_stable_correct == 0:
        sides.append(("planted FAIL cell", "a lost detection"))
    if protected.pass_stable_correct == 0:
        sides.append(("PASS cell", "a new false positive"))
    return sides


def exploratory_commit_refusal(baseline: Baseline, commit: str) -> list[str]:
    """A baseline is confirmed at the commit of its first recording. A change that lands while
    it is exploratory, a label revision included, resets it: the file is deleted and recorded
    again twice at the new commit.
    """
    if baseline.status != BaselineStatus.EXPLORATORY or baseline.commit == commit:
        return []
    return [
        f"the exploratory baseline was recorded at {baseline.commit}, this run at "
        f"{commit}: confirm it at its own commit, or delete it in a commit of its own"
    ]


def condition_refusals(baseline: Baseline, candidate: BaselineConditions) -> list[str]:
    mismatches = condition_mismatches(baseline.conditions, candidate)
    if not mismatches:
        return []
    return [
        f"conditions differ from the {baseline.status} baseline ({'; '.join(mismatches)}): "
        f"to run at other conditions without changing the baseline, pass --ungated. To change "
        f"the baseline's conditions, {_RESET_PROCEDURE}"
    ]


def _confirmed_refusals(existing: Baseline, recording: Recording, gate: GateResult) -> list[str]:
    reasons = condition_refusals(existing, recording.conditions)
    if gate.verdict != GateVerdict.GREEN:
        reasons.append(f"the gate is {gate.verdict}")
    reasons += [
        f"gated cell {key} flipped in this run ({comparison.outcome})"
        for key, comparison in gate.cells.items()
        if comparison.outcome in _FLIPPED
    ]
    return reasons


def _second_recording(existing: Baseline, recording: Recording) -> Baseline:
    disagreements = _disagreements(existing, recording)
    if disagreements:
        return _baseline_from(
            recording, BaselineStatus.EXPLORATORY, existing.replay_rule
        ).model_copy(update={"replaces": _ref(existing), "disagreements": disagreements})
    return _baseline_from(recording, BaselineStatus.CONFIRMED, existing.replay_rule).model_copy(
        update={"confirms": _ref(existing)}
    )


def _disagreements(existing: Baseline, recording: Recording) -> list[str]:
    first = existing.observation_runs()
    return sorted(
        cell_key(cell)
        for cell, seen in first[0].items()
        if all(run[cell] == seen for run in first)
        and any(run.get(cell) != seen for run in recording.runs)
    )


def _baseline_from(recording: Recording, status: BaselineStatus, rule: ReplayRule) -> Baseline:
    return Baseline(
        status=status,
        conditions=recording.conditions,
        replay_rule=rule,
        commit=recording.commit,
        recorded_at=recording.recorded_at,
        runs=[{cell_key(cell): obs for cell, obs in run.items()} for run in recording.runs],
        metrics=recording.metrics,
    )


def _ref(baseline: Baseline) -> RecordingRef:
    return RecordingRef(commit=baseline.commit, recorded_at=baseline.recorded_at)


def gated_set_changes(
    old: Baseline | None, new: Baseline, ground_truth: GroundTruth
) -> GatedSetChange:
    before = _gated_set(old, ground_truth) if old else set[str]()
    after = _gated_set(new, ground_truth)
    return GatedSetChange(entering=sorted(after - before), leaving=sorted(before - after))


def _gated_set(baseline: Baseline, ground_truth: GroundTruth) -> set[str]:
    states = classify(baseline.observation_runs(), ground_truth)
    return {cell_key(cell) for cell, state in states.items() if state == CellState.STABLE_CORRECT}
