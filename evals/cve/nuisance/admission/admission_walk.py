"""The admission's agreement with the walk: every admitted server reached by it through its
recorded reaching flaw (a nuisance acceptance server aside, admitted outside it), no more
servers entering through the addition than its logged size, and each exit the admission records
on a server the walk lists, unmarked, not admitted and recorded once, for a reason the walk does
not derive.
"""

from collections import Counter
from collections.abc import Sequence

from evals.cve.nuisance.admission import walk as nuisance_walk
from evals.cve.nuisance.admission.admission import AdmittedServer, NuisanceAdmission
from evals.cve.nuisance.admission.walk_record import WalkInputs
from evals.cve.nuisance.exits import EXIT_REASON_TEXTS, ExitReason, RecordedExit


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


def standing_exit(server: AdmittedServer) -> ExitReason | None:
    if not server.runs_over_stdio:
        return ExitReason.NOT_OVER_STDIO
    if not server.runs_under_docker:
        return ExitReason.NOT_UNDER_DOCKER
    return None


def exit_problems(admission: NuisanceAdmission, walk_inputs: WalkInputs) -> list[str]:
    reached = nuisance_walk.reached_servers(walk_inputs)
    return [
        *_unlisted_exits(admission.exits, reached),
        *_repeated_exits(admission.exits),
        *_admitted_exits(admission),
        *_derived_reason_exits(admission.exits),
    ]


def _unlisted_exits(
    exits: Sequence[RecordedExit], reached: nuisance_walk.ReachedServers
) -> list[str]:
    """A recorded exit on a server the walk does not list, or on one whose exit it derives."""
    marks = {server.server_package: server.mark for server in reached.listed}
    derived = set(reached.without_candidates)
    problems: list[str] = []
    for recorded in exits:
        package = recorded.server_package
        if package in derived:
            problems.append(
                f"{package}: recorded exit for a server the walk reaches with no flaw that may "
                f"count, whose exit it derives ({EXIT_REASON_TEXTS[ExitReason.NO_COUNTED_FLAW]})"
            )
        elif package not in marks:
            problems.append(f"{package}: recorded exit for a server the walk does not reach")
        elif (mark := marks[package]) is not None:
            problems.append(
                f"{package}: recorded exit for a server the walk marks ({EXIT_REASON_TEXTS[mark]})"
            )
    return problems


def _repeated_exits(exits: Sequence[RecordedExit]) -> list[str]:
    counts = Counter(recorded.server_package for recorded in exits)
    return [f"{package}: {n} recorded exits" for package, n in counts.items() if n > 1]


def _admitted_exits(admission: NuisanceAdmission) -> list[str]:
    admitted = {server.server_package for server in admission.servers}
    return [
        f"{recorded.server_package}: admitted and recorded out "
        f"({EXIT_REASON_TEXTS[recorded.reason]})"
        for recorded in admission.exits
        if recorded.server_package in admitted
    ]


def _derived_reason_exits(exits: Sequence[RecordedExit]) -> list[str]:
    return [
        f"{recorded.server_package}: recorded exit for the reason "
        f"'{EXIT_REASON_TEXTS[recorded.reason]}', which only the walk derives"
        for recorded in exits
        if recorded.reason == ExitReason.ACCEPTANCE_TARGET_SERVER
    ]
