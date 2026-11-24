"""The result of one holdout target, assembled from its run outcomes: pure, statuses and cost."""

from collections.abc import Sequence
from datetime import date

from evals.cve.detection.holdout_audit import IncompleteRun
from evals.cve.detection.holdout_results import DetectionHoldoutRunStatus, HoldoutTargetResult
from evals.cve.detection.session_model import GradedAudit
from evals.cve.detection.targets import Target
from evals.cve.grammar import DETECTION_RUNGS, RunGrade
from evals.cve.kit.target import LaunchMode
from evals.pricing import AuditPrices


def assemble_target(
    target: Target,
    outcomes: Sequence[GradedAudit | IncompleteRun],
    disclosure_date: date,
    prices: AuditPrices,
) -> HoldoutTargetResult:
    reports = [outcome.report for outcome in outcomes]
    return HoldoutTargetResult(
        flaw_id=target.flaw_id,
        disclosure_date=disclosure_date,
        class_labels=tuple(sorted(m.value for m in target.classes)),
        tools_count=len(reports[0].tool_reports),
        ran_in_fallback=target.launch_mode is LaunchMode.FALLBACK,
        statuses=tuple(_run_status(outcome) for outcome in outcomes),
        run_cost=sum(prices.cost(report.generator_usage, report.judge_usage) for report in reports),
    )


def _run_status(outcome: GradedAudit | IncompleteRun) -> DetectionHoldoutRunStatus:
    if isinstance(outcome, IncompleteRun):
        return _incomplete_status(outcome)
    grade = outcome.grade
    return DetectionHoldoutRunStatus(
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
        relaunches=outcome.health.relaunches,
        unsent_calls=outcome.health.unsent_calls,
        cut_responses=outcome.health.cut_responses,
        unchecked_reason=None
        if outcome.unchecked_reason is None
        else outcome.unchecked_reason.value,
        replay_attempt_failures=[failure.value for failure in outcome.replay_attempt_failures],
        missed_call_causes=[],
    )


def _incomplete_status(run: IncompleteRun) -> DetectionHoldoutRunStatus:
    return DetectionHoldoutRunStatus(
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
        relaunches=run.health.relaunches,
        unsent_calls=run.health.unsent_calls,
        cut_responses=run.health.cut_responses,
        unchecked_reason=None,
        replay_attempt_failures=[],
        missed_call_causes=sorted({missed.cause.value for missed in run.report.missed_model_calls}),
    )


def _detected_if_unchecked_missed(grade: RunGrade) -> bool:
    return (grade.status_if_unchecked_missed or grade.status) in DETECTION_RUNGS
