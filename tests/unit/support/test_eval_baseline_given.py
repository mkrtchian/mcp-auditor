from evals.baseline import Baseline, BaselineConditions, BaselineStatus, FixtureConditions
from evals.gate import Cell, Observation, ReplayRule, cell_key
from evals.metrics import EvalMetrics
from mcp_auditor.domain.models import AuditCategory

VULNERABLE_CELL: Cell = ("get_user", AuditCategory.INPUT_VALIDATION)
SAFE_CELL: Cell = ("get_user", AuditCategory.INJECTION)

SERVER_SOURCE = '''import json


def get_user(user_id: str) -> str:
    """Return the user."""
    return json.dumps({"id": user_id})
'''


def conditions(budget: int = 10, source_fingerprint: str = "abc") -> BaselineConditions:
    return BaselineConditions(
        runs=3,
        budget=budget,
        provider="google",
        model="gemini-3.1-flash-lite",
        judge_model="gemini-3.1-flash-lite",
        ground_truth_fingerprint="def",
        fixtures={
            "honeypot": FixtureConditions(
                source_fingerprint=source_fingerprint, chain_budget=0, max_chain_steps=3
            ),
            "chain_honeypot": FixtureConditions(
                source_fingerprint="ghi", chain_budget=3, max_chain_steps=5
            ),
        },
    )


def a_baseline() -> Baseline:
    runs = [
        {VULNERABLE_CELL: Observation.FAIL, SAFE_CELL: Observation.PASS},
        {VULNERABLE_CELL: Observation.UNCOVERED, SAFE_CELL: Observation.PASS},
    ]
    return Baseline(
        status=BaselineStatus.EXPLORATORY,
        conditions=conditions(),
        replay_rule=ReplayRule(),
        commit="0123abc",
        recorded_at="2026-09-23T10:00:00+00:00",
        runs=[{cell_key(cell): observation for cell, observation in run.items()} for run in runs],
        metrics=EvalMetrics(recall=0.9, precision=0.8, consistency=0.7, distribution_coverage=0.95),
    )
