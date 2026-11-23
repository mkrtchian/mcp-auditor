"""The admission's agreement with the nuisance walk: every admitted server reached by it through
its recorded reaching flaw (a nuisance acceptance server aside, admitted outside it), no more
servers entering through the addition than its logged size, and each exit the admission records
on a server the nuisance walk lists, unmarked, not admitted and recorded once, for a reason the
nuisance walk does not derive.
"""

from collections import Counter
from collections.abc import Mapping, Sequence

from evals.cve.nuisance.admission import walk as nuisance_walk
from evals.cve.nuisance.admission.admission import AdmittedServer, NuisanceAdmission
from evals.cve.nuisance.admission.walk_record import WalkInputs
from evals.cve.nuisance.exits import EXIT_REASON_TEXTS, ExitReason, RecordedExit


def walk_problems(admission: NuisanceAdmission, walk_inputs: WalkInputs) -> list[str]:
    population = nuisance_walk.nuisance_population(walk_inputs)
    acceptance_target_servers = nuisance_walk.acceptance_target_servers(walk_inputs)
    size = walk_inputs.record.addition.size
    return [
        *_reach_problems(admission, population, acceptance_target_servers),
        *(
            f"{server.server_package}: enters through the addition past its {size} servers"
            for server in addition_entries(admission, population)[size:]
        ),
    ]


def _reach_problems(
    admission: NuisanceAdmission,
    population: Sequence[nuisance_walk.NuisanceServer],
    acceptance_target_servers: set[str],
) -> list[str]:
    walked = {server.server_package: server for server in population}
    problems: list[str] = []
    for server in admission.servers:
        package = server.server_package
        if package in acceptance_target_servers:
            continue
        walked_server = walked.get(package)
        if walked_server is None:
            problems.append(f"{package}: not reached by the nuisance walk")
        elif walked_server.reaching_flaw != server.reaching_flaw:
            problems.append(
                f"{package}: reaching flaw {server.reaching_flaw} is not the nuisance walk's "
                f"{walked_server.reaching_flaw}"
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
        if (walked_server := walked.get(server.server_package)) is not None
        and walked_server.in_addition
        and walked_server.mark is None
        and server.standing_exit is None
    ]
    return sorted(entries, key=lambda server: walked[server.server_package].reaching_position)


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
    """A recorded exit on a server the nuisance walk does not list, or on one whose exit it
    derives."""
    marks = {server.server_package: server.mark for server in reached.listed}
    derived = set(reached.without_candidates)
    problems = (_unlisted_exit(recorded.server_package, marks, derived) for recorded in exits)
    return [problem for problem in problems if problem is not None]


def _unlisted_exit(
    package: str, marks: Mapping[str, ExitReason | None], derived: set[str]
) -> str | None:
    if package in derived:
        return (
            f"{package}: recorded exit for a server the nuisance walk reaches with no flaw "
            "that may count, whose exit it derives "
            f"({EXIT_REASON_TEXTS[ExitReason.NO_COUNTED_FLAW]})"
        )
    if package not in marks:
        return f"{package}: recorded exit for a server the nuisance walk does not reach"
    mark = marks[package]
    if mark is None:
        return None
    return (
        f"{package}: recorded exit for a server the nuisance walk marks ({EXIT_REASON_TEXTS[mark]})"
    )


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
        f"'{EXIT_REASON_TEXTS[recorded.reason]}', which only the nuisance walk derives"
        for recorded in exits
        if recorded.reason == ExitReason.ACCEPTANCE_TARGET_SERVER
    ]
