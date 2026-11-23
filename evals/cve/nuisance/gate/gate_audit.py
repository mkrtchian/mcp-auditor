from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from evals.cve.audit_attempts import (
    AttemptOutcome,
    IncompleteAttempt,
    MissedCallWording,
    graded_despite_missed_model_calls,
)
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.audit import DroppedRun, NuisanceAudit, incomplete_causes, is_incomplete
from evals.cve.nuisance.counter import flagged_tools
from evals.cve.nuisance.counting import counted_tools
from mcp_auditor.domain.models import AuditReport

_GATE_WORDING = MissedCallWording("no counted alarm, attempted again", "run did not complete")


@dataclass(frozen=True)
class GateRun:
    flagged: bool
    report: AuditReport


async def gate_run(
    server: AdmittedServer, audit: Callable[[], Awaitable[NuisanceAudit | DroppedRun]]
) -> GateRun | None:
    """One run of the nuisance gate, at most `INCOMPLETE_ATTEMPTS` audits: the detection gate's
    policy on an incomplete attempt, with an alarm in place of a detection, unlike the nuisance
    holdout run's. A counted alarm stands whatever model call was missed, an incomplete audit
    without one is attempted again, and the run does not complete when every attempt stays
    incomplete."""

    async def attempt() -> AttemptOutcome[GateRun]:
        outcome = await audit()
        if isinstance(outcome, DroppedRun):
            return None
        report = outcome.report
        flagged = bool(flagged_tools(report, counted_tools(server)))
        if not flagged and is_incomplete(report):
            return IncompleteAttempt(report, incomplete_causes(report))
        return GateRun(flagged=flagged, report=report)

    return await graded_despite_missed_model_calls(server.server_package, attempt, _GATE_WORDING)
