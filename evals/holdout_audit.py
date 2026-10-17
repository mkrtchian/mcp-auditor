"""The holdout refusal and error policy, opposite to acceptance: a refused run stands as a
non-detection and is never retried, only an infra failure is retried."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from rich.console import Console

from evals.cve_audit import IncompleteAttempt, describe_miss_causes
from evals.cve_session_model import GradedAudit
from evals.cve_targets import CVETarget
from mcp_auditor.domain.models import AuditReport

console = Console()

HOLDOUT_INFRA_ATTEMPTS = 3  # one try, two retries


@dataclass(frozen=True)
class IncompleteRun:
    """A run with a missed step and no detection, counted as not detected and never retried. The
    report is kept only for its usage and tools count."""

    report: AuditReport


async def holdout_audit(
    target: CVETarget, attempt: Callable[[], Awaitable[GradedAudit | IncompleteAttempt | None]]
) -> GradedAudit | IncompleteRun | None:
    """One run of one target. A detection stands whatever step was refused. A refusal with no
    detection is a non-detection, not retried (unlike acceptance's keep-best-of-several). An
    infra failure is retried, at most `HOLDOUT_INFRA_ATTEMPTS` calls in all."""
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
        console.print(
            f"[yellow]{target.cve_id}: run failed to launch,"
            f" attempt {number}/{HOLDOUT_INFRA_ATTEMPTS}[/yellow]"
        )
    return None
