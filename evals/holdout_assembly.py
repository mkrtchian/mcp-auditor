"""The result of one holdout target, assembled from its run outcomes: pure, statuses and cost."""

from collections.abc import Sequence
from datetime import date

from evals.cve_grammar import DETECTION_RUNGS, RunGrade
from evals.cve_session_model import GradedAudit
from evals.cve_targets import CVETarget, LaunchMode
from evals.holdout_audit import IncompleteRun
from evals.holdout_conditions import HoldoutConditions
from evals.holdout_results import HoldoutRunStatus, HoldoutTargetResult
from evals.probe import call_cost
from evals.probe_candidates import Prices
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import AuditReport


def holdout_prices(conditions: HoldoutConditions, settings: Settings) -> tuple[Prices, Prices]:
    prices = conditions.prices
    return prices[settings.resolve_model()], prices[settings.resolve_judge_model()]


def assemble_target(
    target: CVETarget,
    outcomes: Sequence[GradedAudit | IncompleteRun],
    disclosure_date: date,
    prices: tuple[Prices, Prices],
) -> HoldoutTargetResult:
    reports = [outcome.report for outcome in outcomes]
    gen_price, judge_price = prices
    return HoldoutTargetResult(
        cve_id=target.cve_id,
        disclosure_date=disclosure_date,
        mechanism_label=None if target.mechanism is None else target.mechanism.value,
        tools_count=len(reports[0].tool_reports),
        ran_in_fallback=target.launch_mode is LaunchMode.FALLBACK,
        statuses=tuple(_run_status(outcome) for outcome in outcomes),
        run_cost=sum(_run_cost(report, gen_price, judge_price) for report in reports),
    )


def _run_status(outcome: GradedAudit | IncompleteRun) -> HoldoutRunStatus:
    if isinstance(outcome, IncompleteRun):
        return _incomplete_status(outcome)
    grade = outcome.grade
    return HoldoutRunStatus(
        detected=grade.status in DETECTION_RUNGS,
        detected_if_unchecked_missed=_detected_if_unchecked_missed(grade),
        surfaced_places=sorted(grade.surfaced_places),
        struck_places=sorted(grade.struck_places),
        unchecked_places=sorted(grade.unchecked_places),
        aimed=grade.aimed,
        fail_without_proof=grade.fail_without_proof,
        incomplete=False,
        non_protocol_lines=outcome.health.non_protocol_lines,
        lost_connection_responses=outcome.health.lost_connection_responses,
        unchecked_reason=None
        if outcome.unchecked_reason is None
        else outcome.unchecked_reason.value,
        replay_attempt_failures=[failure.value for failure in outcome.replay_attempt_failures],
        miss_causes=[],
    )


def _incomplete_status(run: IncompleteRun) -> HoldoutRunStatus:
    return HoldoutRunStatus(
        detected=False,
        detected_if_unchecked_missed=False,
        surfaced_places=[],
        struck_places=[],
        unchecked_places=[],
        aimed=False,
        fail_without_proof=False,
        incomplete=True,
        non_protocol_lines=run.health.non_protocol_lines,
        lost_connection_responses=run.health.lost_connection_responses,
        unchecked_reason=None,
        replay_attempt_failures=[],
        miss_causes=sorted({missed.cause.value for missed in run.report.missed_steps}),
    )


def _detected_if_unchecked_missed(grade: RunGrade) -> bool:
    return (grade.status_if_unchecked_missed or grade.status) in DETECTION_RUNGS


def _run_cost(report: AuditReport, gen_price: Prices, judge_price: Prices) -> float:
    return call_cost(report.generator_usage, gen_price) + call_cost(report.judge_usage, judge_price)
