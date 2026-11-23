"""Whether a recording of the judge eval is written, and as what: the judge's own recording
decision, which applies the shared rules of `evals/recording.py` (ADR 020, 022, 023) to cases."""

from pydantic import BaseModel

from evals.baseline import BaselineStatus, RecordingRef
from evals.gate import Observation, RetestRule, protected_cells
from evals.gate_outcome import GateOutcome
from evals.judge.baseline import JudgeBaseline, JudgeConditions, judge_condition_mismatches
from evals.judge.gate import JudgeGateResult
from evals.recording import (
    FLIPPED_OUTCOMES,
    NOT_MADE_AGAIN,
    RecordingRefused,
    blind_sides,
    conditions_differ_refusal,
    disagreements,
    unconfirmed_commit_refusal,
)
from mcp_auditor.domain.models import EvalVerdict

_RESET_PROCEDURE = (
    "reset the baseline under ADR 020: delete its file in the commit that makes the change, "
    "with no other change in that commit, and record twice at that commit (unconfirmed, then "
    "confirmed). If the gate was red, name the cases whose flip fired it at the last run in the "
    "commit message: each must come out stable and correct in the confirmed baseline, or the "
    "change is reverted. Runs change and a new draw is made only from a green gate (ADR 025)"
)

_FAIL_SIDE, _PASS_SIDE = "FAIL case", "PASS case"


class JudgeRecording(BaseModel):
    conditions: JudgeConditions
    commit: str
    recorded_at: str
    runs: list[dict[str, Observation]]
    ground_truth: dict[str, EvalVerdict]
    retest_rule: RetestRule = RetestRule()


def decide_judge_recording(
    existing: JudgeBaseline | None, recording: JudgeRecording, gate: JudgeGateResult
) -> JudgeBaseline | RecordingRefused:
    if existing is not None and existing.status == BaselineStatus.UNCONFIRMED:
        return _second_recording(existing, recording, gate)
    reasons = _refusals(existing, recording, gate)
    if reasons:
        return RecordingRefused(reasons=reasons)
    if existing is None:
        return _baseline_from(recording, BaselineStatus.UNCONFIRMED, recording.retest_rule)
    return _baseline_from(recording, BaselineStatus.CONFIRMED, existing.retest_rule).model_copy(
        update={"replaces": RecordingRef.of(existing)}
    )


def _refusals(
    existing: JudgeBaseline | None, recording: JudgeRecording, gate: JudgeGateResult
) -> list[str]:
    reasons = _uncovered(recording.runs) + [
        f"{name} under its floor" for name in gate.floor_breaches
    ]
    reasons += [
        f"no {side} is stable and correct: the gate could not see {miss}"
        for side, miss in blind_sides(
            protected_cells(recording.runs, recording.ground_truth), _FAIL_SIDE, _PASS_SIDE
        )
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
    if gate.outcome != GateOutcome.GREEN:
        reasons.append(f"the gate is {gate.outcome}")
    reasons += [
        f"gated case {case} flipped in this run ({comparison.outcome})"
        for case, comparison in gate.cases.items()
        if comparison.outcome in FLIPPED_OUTCOMES
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
        for side, _ in blind_sides(
            protected_cells(baseline.runs, ground_truth), _FAIL_SIDE, _PASS_SIDE
        )
    ]


def judge_condition_refusals(baseline: JudgeBaseline, candidate: JudgeConditions) -> list[str]:
    mismatches = judge_condition_mismatches(baseline.conditions, candidate)
    return conditions_differ_refusal(baseline, mismatches, _RESET_PROCEDURE)


def _second_recording(
    existing: JudgeBaseline, recording: JudgeRecording, gate: JudgeGateResult
) -> JudgeBaseline | RecordingRefused:
    """The second recording adds its runs to the first, and a case is stable only if every run
    of both gives it the same observation (ADR 023)."""
    combined = recording.model_copy(update={"runs": existing.runs + recording.runs})
    reasons = _second_recording_refusals(existing, combined, gate)
    if reasons:
        return RecordingRefused(reasons=reasons)
    return _baseline_from(combined, BaselineStatus.CONFIRMED, existing.retest_rule).model_copy(
        update={
            "confirms": RecordingRef.of(existing),
            "disagreements": sorted(disagreements(existing.runs, recording.runs)),
        }
    )


def _second_recording_refusals(
    existing: JudgeBaseline, combined: JudgeRecording, gate: JudgeGateResult
) -> list[str]:
    """The floors read the second recording's own runs, through `gate`."""
    protected = protected_cells(combined.runs, combined.ground_truth)
    not_made_again = [f"{name} under its floor" for name in gate.floor_breaches] + [
        f"no {side} is stable and correct over the runs of both recordings: the gate could not "
        f"see {miss}"
        for side, miss in blind_sides(protected, _FAIL_SIDE, _PASS_SIDE)
    ]
    return (
        _uncovered(combined.runs)
        + not_made_again
        + unconfirmed_commit_refusal(existing, combined.commit)
        + judge_condition_refusals(existing, combined.conditions)
        + ([NOT_MADE_AGAIN] if not_made_again else [])
    )


def _baseline_from(
    recording: JudgeRecording, status: BaselineStatus, rule: RetestRule
) -> JudgeBaseline:
    return JudgeBaseline(
        status=status,
        conditions=recording.conditions,
        retest_rule=rule,
        commit=recording.commit,
        recorded_at=recording.recorded_at,
        runs=recording.runs,
        protected=protected_cells(recording.runs, recording.ground_truth),
    )
