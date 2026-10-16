"""The holdout refusal and error policy, opposite to acceptance: a refused run stands as a
non-detection and is never retried, only an infra failure is retried."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from rich.console import Console

from evals.cve_audit import RefusedAttempt
from evals.cve_session_model import GradedAudit
from evals.cve_targets import CVETarget
from mcp_auditor.domain.models import AuditReport

console = Console()

HOLDOUT_INFRA_ATTEMPTS = 3  # one try, two retries


@dataclass(frozen=True)
class RefusedRun:
    """A run whose step the provider refused, counted as not detected and never retried. The
    report is kept only for its usage and tools count."""

    report: AuditReport


async def holdout_audit(
    target: CVETarget, attempt: Callable[[], Awaitable[GradedAudit | RefusedAttempt | None]]
) -> GradedAudit | RefusedRun | None:
    """One run of one target. A detection stands whatever step was refused. A refusal with no
    detection is a non-detection, not retried (unlike acceptance's keep-best-of-several). An
    infra failure, whether a launch that returns `None` or any raised error, is retried, at most
    `HOLDOUT_INFRA_ATTEMPTS` calls in all."""

    async def one() -> GradedAudit | RefusedRun | None:
        outcome = await attempt()
        if isinstance(outcome, RefusedAttempt):  # a refusal stops here, non-None, no retry
            console.print(
                f"[yellow]{target.cve_id}: refused by the model provider, counted as not"
                " detected[/yellow]"
            )
            return RefusedRun(outcome.report)
        return outcome

    return await retry_infra(one, f"{target.cve_id}: run failed")


async def retry_infra[T](attempt: Callable[[], Awaitable[T | None]], label: str) -> T | None:
    """Re-run an infra-bound awaitable up to `HOLDOUT_INFRA_ATTEMPTS` times, returning its first
    non-`None` result or `None` on exhaustion. A raised exception and a `None` result both count
    as an attempt and are retried. Only the exception's class name is printed, never `str(exc)`:
    its message could echo server output, which a holdout run must never write (the rule's
    "Reading")."""
    for number in range(1, HOLDOUT_INFRA_ATTEMPTS + 1):
        try:
            result = await attempt()
        except Exception as exc:
            console.print(
                f"[yellow]{label}: {type(exc).__name__},"
                f" attempt {number}/{HOLDOUT_INFRA_ATTEMPTS}[/yellow]"
            )
            continue
        if result is not None:
            return result
        console.print(
            f"[yellow]{label} to launch, attempt {number}/{HOLDOUT_INFRA_ATTEMPTS}[/yellow]"
        )
    return None
