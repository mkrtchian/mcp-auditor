"""The status line of each finished run of a nuisance server: flagged, not flagged or dropped,
with the runs done out of the total. A status per run, which the nuisance suite rule (Reading)
says spends nothing: no count of alarms, no proof text, no per-case verdict."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from rich.markup import escape

from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.audit import DroppedRun, NuisanceAudit, is_incomplete
from evals.cve.nuisance.counter import flagged_tools
from evals.cve.nuisance.counting import counted_tools
from evals.cve.nuisance.results import DROPPED_RUN_REASONS
from evals.eval_display import console

type Audit = Callable[[AdmittedServer], Awaitable[NuisanceAudit | DroppedRun]]


@dataclass(frozen=True)
class RunCount:
    done: int
    total: int


def announcing(audit: Audit, announce: Callable[[str], None], total: int) -> Audit:
    done = 0  # every run resumes on the one event loop, so no lock

    async def announced(server: AdmittedServer) -> NuisanceAudit | DroppedRun:
        nonlocal done
        outcome = await audit(server)
        done += 1
        announce(run_status_line(server, outcome, RunCount(done, total)))
        return outcome

    return announced


def run_status_line(
    server: AdmittedServer, outcome: NuisanceAudit | DroppedRun, count: RunCount
) -> str:
    return f"{server.server_package}: {_status(server, outcome)} [{count.done}/{count.total} runs]"


def _status(server: AdmittedServer, outcome: NuisanceAudit | DroppedRun) -> str:
    if isinstance(outcome, DroppedRun):
        return f"run dropped ({DROPPED_RUN_REASONS[outcome.cause]})"
    report = outcome.report
    status = "flagged" if flagged_tools(report, counted_tools(server)) else "not flagged"
    return f"{status}, incomplete" if is_incomplete(report) else status


def print_run_status(line: str) -> None:
    console.print(escape(line))
