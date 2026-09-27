from evals.gate import (
    CellComparison,
    CellOutcome,
    Observation,
    ProtectedCells,
    cell_key,
)
from evals.gate_verdict import GateMode, GateResult, GateVerdict
from evals.ground_truth import GroundTruth
from evals.metrics import EvalMetrics
from evals.recording import Recording
from tests.unit.support.test_eval_baseline_given import (
    RECORDED_COMMIT,
    SAFE_CELL,
    VULNERABLE_CELL,
    ObservationRuns,
    a_baseline,
    a_ground_truth,
    all_correct_runs,
    conditions,
    runs_where_vulnerable_cell_is,
)

__all__ = [
    "RECORDED_COMMIT",
    "SAFE_CELL",
    "VULNERABLE_CELL",
    "a_baseline",
    "a_ground_truth",
    "all_correct_runs",
    "runs_where_vulnerable_cell_is",
]


def runs_where_safe_cell_is(observation: Observation) -> ObservationRuns:
    return [{VULNERABLE_CELL: Observation.FAIL, SAFE_CELL: observation} for _ in range(3)]


def a_recording(
    runs: ObservationRuns | None = None,
    commit: str = RECORDED_COMMIT,
    completed_all: bool = True,
    budget: int = 10,
    protected: ProtectedCells | None = None,
    ground_truth: GroundTruth | None = None,
) -> Recording:
    return Recording(
        conditions=conditions(budget=budget),
        commit=commit,
        recorded_at="2026-09-23T12:00:00+00:00",
        runs=all_correct_runs() if runs is None else runs,
        metrics=EvalMetrics(recall=0.9, precision=0.9, consistency=0.9, distribution_coverage=0.9),
        completed_all=completed_all,
        protected=protected or protected_on_both_sides(),
        ground_truth=ground_truth or a_ground_truth(),
    )


def protected_on_both_sides() -> ProtectedCells:
    return ProtectedCells(
        fail_stable_correct=1, fail_total=1, pass_stable_correct=1, pass_total=1, unstable=0
    )


def no_stable_and_correct_fail_cell() -> ProtectedCells:
    return protected_on_both_sides().model_copy(update={"fail_stable_correct": 0})


def no_stable_and_correct_pass_cell() -> ProtectedCells:
    return protected_on_both_sides().model_copy(update={"pass_stable_correct": 0})


def a_gate(
    verdict: GateVerdict = GateVerdict.GREEN,
    floor_breaches: list[str] | None = None,
    vulnerable_cell_outcome: CellOutcome = CellOutcome.UNCHANGED,
    mode: GateMode = GateMode.PAIRED,
) -> GateResult:
    return GateResult(
        mode=mode,
        verdict=verdict,
        reasons=[],
        baseline_status=None,
        cells={cell_key(VULNERABLE_CELL): CellComparison(outcome=vulnerable_cell_outcome)},
        floors={},
        thresholds={},
        floor_breaches=floor_breaches or [],
        deltas={},
    )
