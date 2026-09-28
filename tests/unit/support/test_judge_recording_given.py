from evals.gate import CellComparison, CellOutcome
from evals.gate_verdict import GateMode, GateVerdict
from evals.judge_gate import JudgeGateResult
from evals.judge_recording import JudgeRecording
from tests.unit.support.test_judge_baseline_given import (
    FAIL_ID,
    PASS_ID,
    RECORDED_COMMIT,
    ObservationRuns,
    a_baseline,
    a_ground_truth,
    conditions,
    correct_runs,
    runs_where,
)

__all__ = [
    "FAIL_ID",
    "PASS_ID",
    "RECORDED_COMMIT",
    "a_baseline",
    "a_ground_truth",
    "correct_runs",
    "runs_where",
]


def a_recording(
    runs: ObservationRuns | None = None, commit: str = RECORDED_COMMIT, runs_claimed: int = 3
) -> JudgeRecording:
    return JudgeRecording(
        conditions=conditions(runs=runs_claimed),
        commit=commit,
        recorded_at="2026-09-28T13:00:00+00:00",
        runs=correct_runs() if runs is None else runs,
        ground_truth=a_ground_truth(),
    )


def a_gate(
    verdict: GateVerdict = GateVerdict.GREEN,
    floor_breaches: list[str] | None = None,
    pass_case_outcome: CellOutcome = CellOutcome.UNCHANGED,
    mode: GateMode = GateMode.PAIRED,
) -> JudgeGateResult:
    return JudgeGateResult(
        mode=mode,
        verdict=verdict,
        reasons=[],
        baseline_status=None,
        cases={PASS_ID: CellComparison(outcome=pass_case_outcome)},
        floor_breaches=floor_breaches or [],
    )
