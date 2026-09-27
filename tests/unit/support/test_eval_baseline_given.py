from evals.baseline import (
    Baseline,
    BaselineConditions,
    BaselineStatus,
    FixtureConditions,
    fingerprint_ground_truth,
)
from evals.gate import (
    Cell,
    Observation,
    ReplayRule,
    cell_key,
)
from evals.ground_truth import GroundTruth
from evals.metrics import EvalMetrics
from tests.unit.support.test_eval_gate_given import SAFE_CELL, VULNERABLE_CELL, a_ground_truth

RECORDED_COMMIT = "0123abc"

SERVER_SOURCE = '''"""A server with one tool."""

import json


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
        reasoning="minimal",
        judge_reasoning="minimal",
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
