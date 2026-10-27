"""The holdout missed-step and error policy, opposite to acceptance: a run with a missed step
stands as a non-detection and is never retried, only an infra failure is retried."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from evals.cve_audit import IncompleteAttempt, ThrottledAttempt, describe_miss_causes
from evals.cve_session_model import GradedAudit
from evals.cve_targets import CVETarget
from evals.eval_display import console
from evals.holdout_results import NotRunCause
from mcp_auditor.domain.models import AuditReport

HOLDOUT_INFRA_ATTEMPTS = 3  # one try, two retries


@dataclass(frozen=True)
class IncompleteRun:
    """A run with a missed step and no detection, counted as not detected and never retried. The
    report is kept only for its usage and tools count."""

    report: AuditReport


@dataclass(frozen=True)
class DroppedRun:
    """A run that never produced a grade, which drops its target from the whole holdout run."""

    cause: NotRunCause


async def holdout_audit(
    target: CVETarget,
    attempt: Callable[[], Awaitable[GradedAudit | IncompleteAttempt | ThrottledAttempt | None]],
) -> GradedAudit | IncompleteRun | DroppedRun:
    """One run of one target. A detection stands whatever step was missed. A missed step with no
    detection is a non-detection, not retried (unlike acceptance's keep-best-of-several). An
    infra failure or a throttled attempt is retried, at most `HOLDOUT_INFRA_ATTEMPTS` calls in
    all, and the run drops as throttled when any of them was."""
    throttled = False
    for number in range(1, HOLDOUT_INFRA_ATTEMPTS + 1):
        outcome = await attempt()
        if isinstance(outcome, GradedAudit):
            return outcome
        if isinstance(outcome, IncompleteAttempt):
            console.print(
                f"[yellow]{target.cve_id}: {describe_miss_causes(outcome.causes)}, counted as"
                " not detected[/yellow]"
            )
            return IncompleteRun(outcome.report)
        throttled = throttled or isinstance(outcome, ThrottledAttempt)
        console.print(
            f"[yellow]{target.cve_id}: {_failure(outcome)},"
            f" attempt {number}/{HOLDOUT_INFRA_ATTEMPTS}[/yellow]"
        )
    return DroppedRun(NotRunCause.THROTTLED if throttled else NotRunCause.LAUNCH_FAILURE)


def _failure(outcome: ThrottledAttempt | None) -> str:
    if outcome is None:
        return "run failed to launch"
    return "throttled by the model provider past every retry"
