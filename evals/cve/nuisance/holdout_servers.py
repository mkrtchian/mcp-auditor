"""The admitted servers a nuisance run audits, and the standing exits it records without auditing.

A nuisance acceptance server, admitted outside the nuisance walk, is never audited by a nuisance
run, since only the gate audits it (nuisance-suite-rule.md, Run conditions and statistic).
"""

from collections.abc import Sequence
from dataclasses import dataclass

from evals.cve.nuisance.admission import AdmittedServer, NuisanceAdmission
from evals.cve.nuisance.admission_walk import standing_exit
from evals.cve.nuisance.results import ServerExit
from evals.cve.nuisance.walk import NuisanceServer, ServerMark


@dataclass(frozen=True)
class RunPopulation:
    """The admitted population partitioned by the rule's exits: the servers the run audits, and
    the standing exits it records without auditing."""

    audited: Sequence[AdmittedServer]
    exits: Sequence[ServerExit]


_MARK_REASONS = {
    ServerMark.EXCLUDED: "an excluded server",
    ServerMark.ACCEPTANCE_TARGET_SERVER: "the server of a current or dropped acceptance target",
}


def run_population(
    walked: Sequence[NuisanceServer], admission: NuisanceAdmission, acceptance: set[str]
) -> RunPopulation:
    """The rule's other exits (no counted flaw, never fixed, no counted tool, spent by a
    reading) never reach the admission file or are refused by `load_admission`, so the log
    carries them, not this partition."""
    marked = {server.server_package: server.mark for server in walked if server.mark is not None}
    outside = [ServerExit(package, _MARK_REASONS[mark]) for package, mark in marked.items()]
    audited: list[AdmittedServer] = []
    for server in admission.servers:
        package = server.server_package
        if package in marked:
            continue
        if package in acceptance:
            outside.append(ServerExit(package, _MARK_REASONS[ServerMark.ACCEPTANCE_TARGET_SERVER]))
            continue
        reason = standing_exit(server)
        if reason is None:
            audited.append(server)
        else:
            outside.append(ServerExit(package, reason))
    return RunPopulation(audited, outside)
