from evals.baseline import (
    Baseline,
    BaselineConditions,
    BaselineStatus,
    FixtureConditions,
    fingerprint_ground_truth,
)
from evals.gate import Cell, CellComparison, CellOutcome, Observation, ReplayRule, cell_key
from evals.gate_verdict import GateMode, GateResult, GateVerdict
from evals.ground_truth import GroundTruth
from evals.metrics import EvalMetrics
from evals.recording import Recording
from tests.unit.support.test_eval_gate_given import SAFE_CELL, VULNERABLE_CELL, a_ground_truth

RECORDED_COMMIT = "0123abc"

SERVER_SOURCE = '''import json


def get_user(user_id: str) -> str:
    """Return the user."""
    return json.dumps({"id": user_id})
'''

ObservationRuns = list[dict[Cell, Observation]]


def conditions(
    budget: int = 10, source_fingerprint: str = "abc", ground_truth: GroundTruth | None = None
) -> BaselineConditions:
    return BaselineConditions(
        runs=3,
        budget=budget,
        provider="google",
        model="gemini-3.1-flash-lite",
        judge_model="gemini-3.1-flash-lite",
        ground_truth_fingerprint=fingerprint_ground_truth(ground_truth or a_ground_truth()),
        fixtures={
            "honeypot": FixtureConditions(
                source_fingerprint=source_fingerprint, chain_budget=0, max_chain_steps=3
            ),
            "chain_honeypot": FixtureConditions(
                source_fingerprint="ghi", chain_budget=3, max_chain_steps=5
            ),
        },
    )


def a_baseline(
    status: BaselineStatus = BaselineStatus.EXPLORATORY,
    runs: ObservationRuns | None = None,
    replay_rule: ReplayRule | None = None,
    ground_truth: GroundTruth | None = None,
) -> Baseline:
    if runs is None:
        runs = runs_where_vulnerable_cell_is(
            Observation.FAIL, Observation.UNCOVERED, Observation.FAIL
        )
    return Baseline(
        status=status,
        conditions=conditions(ground_truth=ground_truth),
        replay_rule=replay_rule or ReplayRule(),
        commit=RECORDED_COMMIT,
        recorded_at="2026-09-23T10:00:00+00:00",
        runs=[{cell_key(cell): observation for cell, observation in run.items()} for run in runs],
        metrics=EvalMetrics(recall=0.9, precision=0.8, consistency=0.7, distribution_coverage=0.95),
    )


def all_correct_runs() -> ObservationRuns:
    return [{VULNERABLE_CELL: Observation.FAIL, SAFE_CELL: Observation.PASS} for _ in range(3)]


def runs_where_vulnerable_cell_is(*observations: Observation) -> ObservationRuns:
    return [
        {VULNERABLE_CELL: observation, SAFE_CELL: Observation.PASS} for observation in observations
    ]


def a_recording(
    runs: ObservationRuns | None = None,
    commit: str = RECORDED_COMMIT,
    completed_all: bool = True,
    budget: int = 10,
) -> Recording:
    return Recording(
        conditions=conditions(budget=budget),
        commit=commit,
        recorded_at="2026-09-23T12:00:00+00:00",
        runs=all_correct_runs() if runs is None else runs,
        metrics=EvalMetrics(recall=0.9, precision=0.9, consistency=0.9, distribution_coverage=0.9),
        completed_all=completed_all,
        ground_truth=a_ground_truth(),
    )


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
