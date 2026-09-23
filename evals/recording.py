from pydantic import BaseModel

from evals.baseline import (
    Baseline,
    BaselineConditions,
    BaselineStatus,
    RecordingRef,
    condition_mismatches,
)
from evals.gate import Cell, CellOutcome, CellState, Observation, ReplayRule, cell_key, classify
from evals.gate_verdict import GateResult, GateVerdict
from evals.ground_truth import GroundTruth
from evals.metrics import EvalMetrics

_MODEL_CHANGE_PROCEDURE = (
    "follow the model-change procedure of ADR 016: run both models, record the delta, "
    "delete the baseline file, record a new exploratory baseline"
)

_FLIPPED = {CellOutcome.FLIP, CellOutcome.REGRESSION, CellOutcome.FLIP_NOT_REPRODUCED}


class Recording(BaseModel):
    """What a run offers to record. Its ground truth is the one the baseline fingerprints."""

    conditions: BaselineConditions
    commit: str
    recorded_at: str
    runs: list[dict[Cell, Observation]]
    metrics: EvalMetrics
    completed_all: bool
    ground_truth: GroundTruth


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
    if existing is None:
        return reasons
    if existing.status == BaselineStatus.EXPLORATORY:
        return (
            reasons
            + exploratory_commit_refusal(existing, recording.commit)
            + _other_conditions(existing, recording)
        )
    return reasons + _confirmed_refusals(existing, recording, gate)


def exploratory_commit_refusal(baseline: Baseline, commit: str) -> list[str]:
    if baseline.status != BaselineStatus.EXPLORATORY or baseline.commit == commit:
        return []
    return [
        f"the exploratory baseline was recorded at {baseline.commit}, this run at "
        f"{commit}: confirm it at its own commit, or delete it in a commit of its own"
    ]


def _other_conditions(existing: Baseline, recording: Recording) -> list[str]:
    mismatches = condition_mismatches(existing.conditions, recording.conditions)
    if not mismatches:
        return []
    return [
        f"conditions differ from the exploratory baseline ({'; '.join(mismatches)}): delete it "
        "in a commit of its own and record a new one, and if a model differs, "
        + _MODEL_CHANGE_PROCEDURE
    ]


def _confirmed_refusals(existing: Baseline, recording: Recording, gate: GateResult) -> list[str]:
    reasons: list[str] = []
    mismatches = condition_mismatches(existing.conditions, recording.conditions)
    if mismatches:
        reasons.append(
            f"conditions differ from the confirmed baseline ({'; '.join(mismatches)}): "
            f"{_MODEL_CHANGE_PROCEDURE}"
        )
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
    first = classify(existing.observation_runs(), recording.ground_truth)
    second = classify(recording.runs, recording.ground_truth)
    return sorted(
        cell_key(cell)
        for cell, state in first.items()
        if state != CellState.UNSTABLE and second[cell] != state
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
