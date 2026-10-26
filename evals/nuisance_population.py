"""The admitted servers a nuisance run audits, and the standing exits it records without auditing.

An acceptance server admitted outside the walk is never audited by a nuisance run, since only the
gate audits it (nuisance-rule.md, Run conditions and statistic).
"""

from collections.abc import Sequence
from dataclasses import dataclass

from evals.nuisance_admission import AdmittedServer, NuisanceAdmission
from evals.nuisance_results import FigureExit
from evals.nuisance_walk import NuisanceServer, ServerMark


@dataclass(frozen=True)
class RunPopulation:
    """The admitted population partitioned by the rule's exits: the servers the run audits, and
    the standing exits it records without auditing."""

    audited: Sequence[AdmittedServer]
    outside_figure: Sequence[FigureExit]


_MARK_REASONS = {
    ServerMark.EXCLUDED: "an excluded server",
    ServerMark.ACCEPTANCE: "an acceptance server",
}


def run_population(
    walked: Sequence[NuisanceServer], admission: NuisanceAdmission, acceptance: set[str]
) -> RunPopulation:
    """The rule's other exits (no flaw sets the version, never fixed, no counted tool, spent by a
    reading) never reach the admission file or are refused by `load_admission`, so the log
    carries them, not this partition."""
    marked = {server.server_package: server.mark for server in walked if server.mark is not None}
    outside = [FigureExit(package, _MARK_REASONS[mark]) for package, mark in marked.items()]
    audited: list[AdmittedServer] = []
    for server in admission.servers:
        package = server.server_package
        if package in marked:
            continue
        if package in acceptance:
            outside.append(FigureExit(package, _MARK_REASONS[ServerMark.ACCEPTANCE]))
            continue
        reason = standing_exit(server)
        if reason is None:
            audited.append(server)
        else:
            outside.append(FigureExit(package, reason))
    return RunPopulation(audited, outside)


def standing_exit(server: AdmittedServer) -> str | None:
    if not server.runs_over_stdio:
        return "does not run over stdio"
    if not server.runs_under_docker:
        return "its patched version does not run under Docker"
    return None
