from evals.gate_verdict import GateMode
from evals.judge_gate import JudgeGateInput
from tests.unit.support.test_judge_baseline_given import (
    FAIL_ID,
    PASS_ID,
    UNSPECIFIED_ID,
    ObservationRuns,
    a_baseline,
    a_ground_truth,
    conditions,
    correct_runs,
    runs_failing_every_case,
    runs_where,
)

__all__ = [
    "FAIL_ID",
    "PASS_ID",
    "UNSPECIFIED_ID",
    "a_baseline",
    "a_ground_truth",
    "conditions",
    "correct_runs",
    "runs_failing_every_case",
    "runs_where",
]


def a_paired_input(
    runs: ObservationRuns,
    replays: dict[str, list[bool]] | None = None,
    declared: frozenset[str] = frozenset(),
    mismatches: list[str] | None = None,
) -> JudgeGateInput:
    """Against a confirmed baseline where every case is stable and correct."""
    return JudgeGateInput(
        mode=GateMode.PAIRED,
        runs=runs,
        ground_truth=a_ground_truth(),
        baseline=a_baseline(),
        replays=replays or {},
        declared=declared,
        mismatches=mismatches or [],
    )
