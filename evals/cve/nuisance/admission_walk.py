"""The admission's agreement with the walk: every admitted server reached by it through its
recorded reaching flaw (a nuisance acceptance server aside, admitted outside it), and no more
servers entering through the addition than its logged size.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from evals.cve.nuisance import walk as nuisance_walk
from evals.cve.nuisance.walk_record import WalkInputs

if TYPE_CHECKING:
    from evals.cve.nuisance.admission import AdmittedServer, NuisanceAdmission


def walk_problems(admission: NuisanceAdmission, walk_inputs: WalkInputs) -> list[str]:
    population = nuisance_walk.nuisance_population(walk_inputs)
    acceptance = nuisance_walk.acceptance_target_servers(walk_inputs)
    size = walk_inputs.record.addition.size
    return [
        *_reach_problems(admission, population, acceptance),
        *(
            f"{server.server_package}: enters through the addition past its {size} servers"
            for server in addition_entries(admission, population)[size:]
        ),
    ]


def _reach_problems(
    admission: NuisanceAdmission,
    population: Sequence[nuisance_walk.NuisanceServer],
    acceptance: set[str],
) -> list[str]:
    walked = {server.server_package: server for server in population}
    problems: list[str] = []
    for server in admission.servers:
        package = server.server_package
        if package in acceptance:
            continue
        reach = walked.get(package)
        if reach is None:
            problems.append(f"{package}: not reached by the walk")
        elif reach.reaching_flaw != server.reaching_flaw:
            problems.append(
                f"{package}: reaching flaw {server.reaching_flaw} is not the walk's "
                f"{reach.reaching_flaw}"
            )
    return problems


def addition_entries(
    admission: NuisanceAdmission, population: Sequence[nuisance_walk.NuisanceServer]
) -> list[AdmittedServer]:
    """The admitted servers that enter the nuisance holdout layer through the addition, in draw
    order."""
    walked = {server.server_package: server for server in population}
    entries = [
        server
        for server in admission.servers
        if (reach := walked.get(server.server_package)) is not None
        and reach.in_addition
        and reach.mark is None
        and standing_exit(server) is None
    ]
    return sorted(entries, key=lambda server: walked[server.server_package].reaching_position)


def standing_exit(server: AdmittedServer) -> str | None:
    if not server.runs_over_stdio:
        return "does not run over stdio"
    if not server.runs_under_docker:
        return "its patched version does not run under Docker"
    return None
