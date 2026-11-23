"""The outcomes of one audit attempt and the gates' policy on a missed model call."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from evals.cve.grammar import DETECTION_RUNGS, RunGrade
from evals.cve.server_health import NO_INCIDENTS, ServerHealth
from evals.eval_display import console
from mcp_auditor.domain.model_calls import MissedCallCause
from mcp_auditor.domain.models import AuditReport

# A missed model call (a policy refusal, an unreadable answer or a prompt longer than the model's
# context window) leaves a run with no detection or counted alarm saying nothing. The generated
# prompts differ from one audit to the next, so a new attempt usually passes the provider's filter
# and gets a readable answer.
INCOMPLETE_ATTEMPTS = 3


@dataclass(frozen=True)
class IncompleteAttempt:
    """An audit whose report holds a missed model call, with its causes, and neither a detection
    nor a counted alarm, which would stand despite it."""

    report: AuditReport
    causes: frozenset[MissedCallCause]
    health: ServerHealth = NO_INCIDENTS


@dataclass(frozen=True)
class ThrottledAttempt:
    """An audit whose report holds a model call throttled past every retry, thrown away ungraded."""


@dataclass(frozen=True)
class ProviderErrorAttempt:
    """An audit stopped by a provider error a later attempt may not meet, thrown away ungraded.
    The description holds the error's type and status, never its message."""

    description: str


# None is a run thrown away at once, such as one skipped at launch.
type AttemptOutcome[T] = T | IncompleteAttempt | ThrottledAttempt | ProviderErrorAttempt | None


@dataclass(frozen=True)
class MissedCallWording:
    """What a gate's console says of an attempt that missed a model call, and of its run."""

    attempt_note: str
    run_note: str


async def graded_despite_missed_model_calls[T](
    label: str,
    attempt: Callable[[], Awaitable[AttemptOutcome[T]]],
    wording: MissedCallWording,
) -> T | None:
    """The first complete attempt grades the run. None when every attempt missed a model call, and
    at once on a throttled attempt or a provider error, as on a run skipped at launch."""
    causes: frozenset[MissedCallCause] = frozenset()
    for number in range(1, INCOMPLETE_ATTEMPTS + 1):
        outcome = await attempt()
        if isinstance(outcome, ThrottledAttempt | ProviderErrorAttempt):
            return None
        if not isinstance(outcome, IncompleteAttempt):
            return outcome
        causes |= outcome.causes
        console.print(
            f"[yellow]{label}: attempt {number}/{INCOMPLETE_ATTEMPTS}:"
            f" {describe_missed_call_causes(outcome.causes)}, {wording.attempt_note}[/yellow]"
        )
    console.print(
        f"[yellow]{label} {wording.run_note}:[/yellow] a model call missed at all"
        f" {INCOMPLETE_ATTEMPTS} attempts ({describe_missed_call_causes(causes)})"
    )
    return None


_CAUSE_WORDING = {
    MissedCallCause.PROVIDER_REFUSAL: "refused by the model provider",
    MissedCallCause.UNREADABLE_ANSWER: "unreadable model answer",
    MissedCallCause.PROMPT_TOO_LONG: "prompt longer than the model's context window",
}


def describe_missed_call_causes(causes: frozenset[MissedCallCause]) -> str:
    return " and ".join(wording for cause, wording in _CAUSE_WORDING.items() if cause in causes)


def graded_or_incomplete(grade: RunGrade, report: AuditReport) -> RunGrade | IncompleteAttempt:
    """A detection carries its own proof and stands whatever model call was missed. A run that
    did not detect with a missed model call says nothing of detection, the struck credit
    included."""
    if report.missed_model_calls and grade.status not in DETECTION_RUNGS:
        return IncompleteAttempt(
            report, frozenset(missed.cause for missed in report.missed_model_calls)
        )
    return grade
