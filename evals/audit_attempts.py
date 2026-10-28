"""The outcomes of one audit attempt and the acceptance missed-step policy that retries them."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from evals.cve_grammar import DETECTION_RUNGS, RunGrade
from evals.cve_targets import CVETarget
from evals.eval_display import console
from evals.server_health import NO_INCIDENTS, ServerHealth
from mcp_auditor.domain.models import AuditReport, MissCause

# A missed step (a policy refusal or an unreadable answer) leaves the run saying nothing of
# detection. The generated prompts differ from one audit to the next, so a new attempt usually
# passes the provider's filter and gets a readable answer.
INCOMPLETE_ATTEMPTS = 3


@dataclass(frozen=True)
class IncompleteAttempt:
    """An audit that did not detect and whose report holds a missed step, with its causes."""

    report: AuditReport
    causes: frozenset[MissCause]
    health: ServerHealth = NO_INCIDENTS


@dataclass(frozen=True)
class ThrottledAttempt:
    """An audit whose report holds a step throttled past every retry, thrown away ungraded."""


@dataclass(frozen=True)
class ProviderErrorAttempt:
    """An audit stopped by a provider error a later attempt may not meet, thrown away ungraded.
    The description holds the error's type and status, never its message."""

    description: str


# None is a run skipped at launch.
type AttemptOutcome[T] = T | IncompleteAttempt | ThrottledAttempt | ProviderErrorAttempt | None


async def graded_despite_missed_steps[T](
    target: CVETarget, attempt: Callable[[], Awaitable[AttemptOutcome[T]]]
) -> T | None:
    """The first complete attempt grades the run. None when every attempt missed a step, and at
    once on a throttled attempt or a provider error, as on a run skipped at launch."""
    causes: frozenset[MissCause] = frozenset()
    for number in range(1, INCOMPLETE_ATTEMPTS + 1):
        outcome = await attempt()
        if isinstance(outcome, ThrottledAttempt | ProviderErrorAttempt):
            return None
        if not isinstance(outcome, IncompleteAttempt):
            return outcome
        causes |= outcome.causes
        console.print(
            f"[yellow]{target.cve_id}: attempt {number}/{INCOMPLETE_ATTEMPTS}:"
            f" {describe_miss_causes(outcome.causes)}, not graded[/yellow]"
        )
    console.print(
        f"[yellow]{target.cve_id} run skipped:[/yellow] a step missed at all"
        f" {INCOMPLETE_ATTEMPTS} attempts ({describe_miss_causes(causes)})"
    )
    return None


_CAUSE_WORDING = {
    MissCause.PROVIDER_REFUSAL: "refused by the model provider",
    MissCause.UNREADABLE_ANSWER: "unreadable model answer",
}


def describe_miss_causes(causes: frozenset[MissCause]) -> str:
    return " and ".join(wording for cause, wording in _CAUSE_WORDING.items() if cause in causes)


def graded_or_incomplete(grade: RunGrade, report: AuditReport) -> RunGrade | IncompleteAttempt:
    """A detection carries its own proof and stands whatever step was missed. A run that did
    not detect with a missed step says nothing of detection, the struck credit included."""
    if report.missed_steps and grade.status not in DETECTION_RUNGS:
        return IncompleteAttempt(report, frozenset(missed.cause for missed in report.missed_steps))
    return grade
