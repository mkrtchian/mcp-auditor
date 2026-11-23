from dataclasses import dataclass

from pydantic import BaseModel

from evals.baseline import BaselineStatus
from evals.gate import Observation
from evals.judge.baseline import JudgeConditions
from evals.judge.fixture import JudgeFixture, ground_truth_of
from evals.judge.gate import CaseRuns, JudgeGateResult
from evals.judge.metrics import (
    CaseResult,
    JudgeMetrics,
    compute_judge_metrics,
    compute_per_category_metrics,
)
from evals.judge.session_model import JudgeSessionResult
from mcp_auditor.domain.models import AuditCategory


class JudgeReport(BaseModel):
    """Precision, recall and F1 are diagnostics: the gate is the case comparison."""

    timestamp: str
    conditions: JudgeConditions
    inputs_fingerprint: str
    per_run: list[JudgeMetrics]
    per_category: dict[AuditCategory, JudgeMetrics]
    gate: JudgeGateResult
    runs: CaseRuns
    retest_observations: dict[str, list[Observation]]
    throttled_judgments: list[str]
    recorded: BaselineStatus | None
    recording_refused: list[str]
    concurrency: int
    throttled_requests: int


@dataclass(frozen=True)
class JudgeRunFacts:
    """What the run adds to the session result: when the report was built, and the requests
    the model provider throttled at the run's concurrency."""

    timestamp: str
    throttled_requests: int
    concurrency: int


def build_judge_report(
    result: JudgeSessionResult, fixture: JudgeFixture, facts: JudgeRunFacts
) -> JudgeReport:
    scored = [_scored_cases(run, fixture) for run in result.runs]
    categories = {case.id: case.inputs.category for case in fixture.cases}
    pooled = [(categories[case], pair) for run in scored for case, pair in run]
    return JudgeReport(
        timestamp=facts.timestamp,
        conditions=result.conditions,
        inputs_fingerprint=result.conditions.inputs_fingerprint,
        per_run=[compute_judge_metrics([pair for _, pair in run]) for run in scored],
        per_category=compute_per_category_metrics(pooled),
        gate=result.gate,
        runs=result.runs,
        retest_observations=result.retest_observations,
        throttled_judgments=result.throttled_judgments,
        recorded=result.written.status if result.written else None,
        recording_refused=result.recording_refused,
        concurrency=facts.concurrency,
        throttled_requests=facts.throttled_requests,
    )


def _scored_cases(
    run: dict[str, Observation], fixture: JudgeFixture
) -> list[tuple[str, CaseResult]]:
    """The labeled cases the judge gave a verdict on, uncovered ones left out."""
    return [
        (case, (verdict, expected))
        for case, expected in ground_truth_of(fixture).items()
        if (verdict := run[case].verdict) is not None
    ]
