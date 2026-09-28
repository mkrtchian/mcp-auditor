"""Whether a recording of the judge isolation eval is written, and as what: the rules of
`evals/recording.py` (ADR 020, 022, 023) with the case in place of the cell."""

from pydantic import BaseModel

from evals.baseline import BaselineStatus, RecordingRef
from evals.gate import CellOutcome, Observation, ProtectedCells, ReplayRule, protected_cells
from evals.gate_verdict import GateVerdict
from evals.judge_baseline import JudgeBaseline, JudgeConditions, judge_condition_mismatches
from evals.judge_gate import JudgeGateResult
from evals.recording import NOT_MADE_AGAIN, RecordingRefused
from mcp_auditor.domain.models import EvalVerdict

_RESET_PROCEDURE = (
    "reset the baseline under ADR 020: delete its file in the commit that makes the change, "
    "with no other change in that commit, and record twice at that commit (exploratory, then "
    "confirmed). If the gate was red, name the cases whose flip fired it at the last run in the "
    "commit message: each must come out stable and correct in the confirmed baseline, or the "
    "change is reverted. Runs change and a new draw is made only from a green gate (ADR 025)"
)

_FLIPPED = {CellOutcome.FLIP, CellOutcome.REGRESSION, CellOutcome.FLIP_NOT_REPRODUCED}


class JudgeRecording(BaseModel):
    conditions: JudgeConditions
    commit: str
    recorded_at: str
    runs: list[dict[str, Observation]]
    ground_truth: dict[str, EvalVerdict]
    replay_rule: ReplayRule = ReplayRule()


def decide_judge_recording(
    existing: JudgeBaseline | None, recording: JudgeRecording, gate: JudgeGateResult
) -> JudgeBaseline | RecordingRefused:
    if existing is not None and existing.status == BaselineStatus.EXPLORATORY:
        return _second_recording(existing, recording, gate)
    reasons = _refusals(existing, recording, gate)
    if reasons:
        return RecordingRefused(reasons=reasons)
    if existing is None:
        return _baseline_from(recording, BaselineStatus.EXPLORATORY, recording.replay_rule)
    return _baseline_from(recording, BaselineStatus.CONFIRMED, existing.replay_rule).model_copy(
        update={"replaces": _ref(existing)}
    )


def _refusals(
    existing: JudgeBaseline | None, recording: JudgeRecording, gate: JudgeGateResult
) -> list[str]:
    reasons = _uncovered(recording.runs) + [
        f"{name} under its floor" for name in gate.floor_breaches
    ]
    reasons += [
        f"no {side} is stable and correct: the gate could not see {miss}"
        for side, miss in _blind_sides(protected_cells(recording.runs, recording.ground_truth))
    ]
    if existing is None:
        return reasons
    return reasons + _confirmed_refusals(existing, recording, gate)


def _uncovered(runs: list[dict[str, Observation]]) -> list[str]:
    cases = sorted(
        {case for run in runs for case, seen in run.items() if seen == Observation.UNCOVERED}
    )
    return [
        f"a judge call failed on case {case}: a baseline holds a verdict for every case in "
        "every run"
        for case in cases
    ]


def _confirmed_refusals(
    existing: JudgeBaseline, recording: JudgeRecording, gate: JudgeGateResult
) -> list[str]:
    reasons = judge_condition_refusals(existing, recording.conditions)
    if gate.verdict != GateVerdict.GREEN:
        reasons.append(f"the gate is {gate.verdict}")
    reasons += [
        f"gated case {case} flipped in this run ({comparison.outcome})"
        for case, comparison in gate.cases.items()
        if comparison.outcome in _FLIPPED
    ]
    return reasons


def judge_rescore_refusals(
    baseline: JudgeBaseline, ground_truth: dict[str, EvalVerdict]
) -> list[str]:
    """A label revision re-scores the stored observations (ADR 020). One that leaves a side with
    no stable and correct case leaves the gate blind on that side: the baseline is reset
    (ADR 022)."""
    return [
        f"under the current labels the baseline holds no stable and correct {side}: delete the "
        f"baseline file in a commit of its own and record twice at that commit (ADR 022)"
        for side, _ in _blind_sides(protected_cells(baseline.runs, ground_truth))
    ]


def _blind_sides(protected: ProtectedCells) -> list[tuple[str, str]]:
    sides: list[tuple[str, str]] = []
    if protected.fail_stable_correct == 0:
        sides.append(("FAIL case", "a lost detection"))
    if protected.pass_stable_correct == 0:
        sides.append(("PASS case", "a new false positive"))
    return sides


def judge_exploratory_commit_refusal(baseline: JudgeBaseline, commit: str) -> list[str]:
    if baseline.status != BaselineStatus.EXPLORATORY or baseline.commit == commit:
        return []
    return [
        f"the exploratory baseline was recorded at {baseline.commit}, this run at "
        f"{commit}: confirm it at its own commit, or delete it in a commit of its own"
    ]


def judge_condition_refusals(baseline: JudgeBaseline, candidate: JudgeConditions) -> list[str]:
    mismatches = judge_condition_mismatches(baseline.conditions, candidate)
    if not mismatches:
        return []
    return [
        f"conditions differ from the {baseline.status} baseline ({'; '.join(mismatches)}): "
        f"to run at other conditions without changing the baseline, pass --ungated. To change "
        f"the baseline's conditions, {_RESET_PROCEDURE}"
    ]


def _second_recording(
    existing: JudgeBaseline, recording: JudgeRecording, gate: JudgeGateResult
) -> JudgeBaseline | RecordingRefused:
    """The second recording adds its runs to the first, and a case is stable only if every run
    of both gives it the same observation (ADR 023)."""
    combined = recording.model_copy(update={"runs": existing.runs + recording.runs})
    reasons = _second_recording_refusals(existing, combined, gate)
    if reasons:
        return RecordingRefused(reasons=reasons)
    return _baseline_from(combined, BaselineStatus.CONFIRMED, existing.replay_rule).model_copy(
        update={"confirms": _ref(existing), "disagreements": _disagreements(existing, recording)}
    )


def _second_recording_refusals(
    existing: JudgeBaseline, combined: JudgeRecording, gate: JudgeGateResult
) -> list[str]:
    """The floors read the second recording's own runs, through `gate`."""
    protected = protected_cells(combined.runs, combined.ground_truth)
    not_made_again = [f"{name} under its floor" for name in gate.floor_breaches] + [
        f"no {side} is stable and correct over the runs of both recordings: the gate could not "
        f"see {miss}"
        for side, miss in _blind_sides(protected)
    ]
    return (
        _uncovered(combined.runs)
        + not_made_again
        + judge_exploratory_commit_refusal(existing, combined.commit)
        + judge_condition_refusals(existing, combined.conditions)
        + ([NOT_MADE_AGAIN] if not_made_again else [])
    )


def _disagreements(existing: JudgeBaseline, recording: JudgeRecording) -> list[str]:
    first = existing.runs
    return sorted(
        case
        for case, seen in first[0].items()
        if all(run[case] == seen for run in first)
        and any(run.get(case) != seen for run in recording.runs)
    )


def _baseline_from(
    recording: JudgeRecording, status: BaselineStatus, rule: ReplayRule
) -> JudgeBaseline:
    return JudgeBaseline(
        status=status,
        conditions=recording.conditions,
        replay_rule=rule,
        commit=recording.commit,
        recorded_at=recording.recorded_at,
        runs=recording.runs,
        protected=protected_cells(recording.runs, recording.ground_truth),
    )


def _ref(baseline: JudgeBaseline) -> RecordingRef:
    return RecordingRef(commit=baseline.commit, recorded_at=baseline.recorded_at)
