"""The admitted servers a nuisance holdout run audits, the exits it records without auditing, and
the reached servers whose admission is pending.

A nuisance acceptance server, admitted outside the nuisance walk, is never audited by a nuisance
holdout run, since only the gate audits it (nuisance-suite-rule.md, Run conditions and statistic).
"""

from collections.abc import Sequence
from dataclasses import dataclass

from evals.cve.nuisance.admission.admission import AdmittedServer, NuisanceAdmission
from evals.cve.nuisance.admission.admission_walk import MARK_REASONS, standing_exit
from evals.cve.nuisance.admission.walk import ReachedServers
from evals.cve.nuisance.exits import ExitReason
from evals.cve.nuisance.results import ServerExit


@dataclass(frozen=True)
class RunPopulation:
    """The reached servers partitioned by the rule's exits: the servers the run audits, the exits
    it records without auditing, and the listed servers neither admitted nor out, which no reason
    of the rule fits until their admission ends."""

    audited: Sequence[AdmittedServer]
    exits: Sequence[ServerExit]
    pending: Sequence[str]


def run_population(
    reached: ReachedServers, admission: NuisanceAdmission, acceptance: set[str]
) -> RunPopulation:
    """The exits the walk derives (its marks, and no counted flaw for a server it reaches with no
    flaw that may count), those of the admitted servers, then those the admission records."""
    marked = {s.server_package: s.mark for s in reached.listed if s.mark is not None}
    outside = [ServerExit(package, MARK_REASONS[mark]) for package, mark in marked.items()]
    outside += [ServerExit(p, ExitReason.NO_COUNTED_FLAW) for p in reached.without_candidates]
    derived = {row.server_package for row in outside}
    audited: list[AdmittedServer] = []
    for server in admission.servers:
        package = server.server_package
        if package in derived:
            continue
        reason = (
            ExitReason.ACCEPTANCE_TARGET_SERVER if package in acceptance else standing_exit(server)
        )
        if reason is None:
            audited.append(server)
        else:
            outside.append(ServerExit(package, reason))
    outside += [ServerExit(row.server_package, row.reason) for row in admission.exits]
    return RunPopulation(audited, outside, _pending(reached, admission))


def _pending(reached: ReachedServers, admission: NuisanceAdmission) -> list[str]:
    settled = {server.server_package for server in admission.servers}
    settled |= {row.server_package for row in admission.exits}
    return [
        server.server_package
        for server in reached.listed
        if server.mark is None and server.server_package not in settled
    ]
