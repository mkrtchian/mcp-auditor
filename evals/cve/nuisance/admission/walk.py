"""The nuisance walk of the salted draw order of evals/census.json.

The nuisance walk reaches every flaw the detection walk reached, whatever its outcome, then resumes
in draw order over the draw-order flaws the detection walk has not reached, skipping one that fails
a draw-order criterion once its settlements apply. It groups the flaws by server (the rule's unit),
an identity settlement of the walk record naming a flaw's server, and keeps a server when at least
one of its census flaws may count: reached through tools, its effect visible in a tool response, and
pinnable. The class is the admission's: no classifier's class nor any class settlement takes a flaw
out here, so a flaw outside the grammar is listed pending the admission's class. Pure reads of the
census, its draw settlements and the walk record, no LLM, no network.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from evals.cve.census.census import CLASSIFIERS, Census
from evals.cve.census.classification import Criterion, Primitive, criteria_met
from evals.cve.census.draw_order import draw_order
from evals.cve.census.exclusions import ACCEPTANCE_TARGET_FLAWS, EXCLUDED_SERVERS
from evals.cve.census.grouping import DRAW_ORDER_CRITERIA
from evals.cve.detection.draw_record import Settlement
from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.cve.nuisance.admission.walk_record import (
    WalkInputs,
    normalized_package,
    reached_identifiers,
)
from evals.cve.nuisance.exits import ExitReason


@dataclass(frozen=True)
class NuisanceServer:
    server_package: str
    reaching_flaw: str
    reaching_position: int
    in_addition: bool
    flaws: tuple[str, ...]
    candidate_counted_flaws: tuple[str, ...]
    mark: ExitReason | None


def nuisance_acceptance_servers(walk_inputs: WalkInputs) -> set[str]:
    classified = _classified(walk_inputs.census)
    return {
        server_of(t.flaw_id, walk_inputs) for t in ACCEPTANCE_TARGETS if t.flaw_id in classified
    }


def server_of(identifier: str, walk_inputs: WalkInputs) -> str:
    server = walk_inputs.server_by_flaw.get(identifier)
    if server is None:
        raise ValueError(f"no classification for flaw {identifier}")
    return server


def _classified(census: Census) -> set[str]:
    return {classification.flaw for classification in census.classifications[CLASSIFIERS[0]]}


@dataclass(frozen=True)
class ReachedServers:
    listed: Sequence[NuisanceServer]  # nuisance_population: what `walk` prints
    without_candidates: Sequence[str]  # reached, with no flaw that may count, in walk order


def reached_servers(walk_inputs: WalkInputs) -> ReachedServers:
    without_candidates = [
        server
        for server in _first_reaches(walk_inputs)
        if not candidate_counted_flaws(server, walk_inputs)
    ]
    return ReachedServers(nuisance_population(walk_inputs), without_candidates)


def candidate_counted_flaws(server_package: str, walk_inputs: WalkInputs) -> list[str]:
    return [
        flaw
        for flaw in census_flaws_of(server_package, walk_inputs)
        if _may_count(flaw, walk_inputs)
    ]


def census_flaws_of(server_package: str, walk_inputs: WalkInputs) -> list[str]:
    return [
        flaw.identifier
        for flaw in walk_inputs.census.flaws
        if server_of(flaw.identifier, walk_inputs) == server_package
    ]


def nuisance_population(walk_inputs: WalkInputs) -> list[NuisanceServer]:
    target_servers = acceptance_target_servers(walk_inputs)
    excluded = {normalized_package(package) for package in EXCLUDED_SERVERS}
    population: list[NuisanceServer] = []
    for server, reach in _first_reaches(walk_inputs).items():
        candidates = candidate_counted_flaws(server, walk_inputs)
        if not candidates:
            continue
        population.append(
            NuisanceServer(
                server_package=server,
                reaching_flaw=reach.flaw,
                reaching_position=reach.position,
                in_addition=reach.in_addition,
                flaws=tuple(census_flaws_of(server, walk_inputs)),
                candidate_counted_flaws=tuple(candidates),
                mark=_mark(server, target_servers, excluded),
            )
        )
    return population


def acceptance_target_servers(walk_inputs: WalkInputs) -> set[str]:
    """The server of every current or dropped acceptance target."""
    classified = _classified(walk_inputs.census)
    return {server_of(flaw, walk_inputs) for flaw in ACCEPTANCE_TARGET_FLAWS if flaw in classified}


@dataclass(frozen=True)
class _Reach:
    flaw: str
    position: int
    in_addition: bool


def _first_reaches(walk_inputs: WalkInputs) -> dict[str, _Reach]:
    reaches: dict[str, _Reach] = {}
    for reach in _walk(walk_inputs):
        reaches.setdefault(server_of(reach.flaw, walk_inputs), reach)
    return reaches


def _walk(walk_inputs: WalkInputs) -> list[_Reach]:
    order = [entry.identifier for entry in draw_order(walk_inputs.census)]
    positions = {identifier: position for position, identifier in enumerate(order, start=1)}
    detection_walk_flaws = reached_identifiers(walk_inputs.census)
    for identifier in detection_walk_flaws:
        if identifier not in positions:
            raise ValueError(f"the detection walk reaches {identifier}, outside the draw order")
    reached = set(detection_walk_flaws)
    queue = [
        identifier
        for identifier in order
        if identifier not in reached and _meets_draw_criteria(identifier, walk_inputs)
    ]
    return [
        *(_Reach(identifier, positions[identifier], False) for identifier in detection_walk_flaws),
        *(_Reach(identifier, positions[identifier], True) for identifier in queue),
    ]


def _meets_draw_criteria(flaw: str, walk_inputs: WalkInputs) -> bool:
    return all(_met(flaw, walk_inputs, criterion) for criterion in DRAW_ORDER_CRITERIA)


def _mark(server: str, target_servers: set[str], excluded: set[str]) -> ExitReason | None:
    if server in target_servers:
        return ExitReason.ACCEPTANCE_TARGET_SERVER
    if server in excluded:
        return ExitReason.EXCLUDED_SERVER
    return None


def _may_count(flaw: str, walk_inputs: WalkInputs) -> bool:
    return (
        _met(flaw, walk_inputs, Criterion.EFFECT_IN_TOOL_RESPONSE)
        and _met(flaw, walk_inputs, Criterion.PINNABLE)
        and _tools_reached(flaw, walk_inputs)
    )


def _met(flaw: str, walk_inputs: WalkInputs, criterion: Criterion) -> bool:
    settlement = _settlement(flaw, walk_inputs, criterion)
    if settlement is not None:
        return settlement.ruling
    seen = walk_inputs.classifications_by_flaw.get(flaw, [])
    return any(criteria_met(c)[criterion] for c in seen)


def _tools_reached(flaw: str, walk_inputs: WalkInputs) -> bool:
    seen = walk_inputs.classifications_by_flaw.get(flaw, [])
    if any(c.primitive == Primitive.TOOLS for c in seen):
        return True
    # A False STDIO_TOOLS_CALL settlement does not override: it may hold for the transport
    # alone (not stdio), and this suite counts a flaw whatever transport the census records.
    settlement = _settlement(flaw, walk_inputs, Criterion.STDIO_TOOLS_CALL)
    return settlement is not None and settlement.ruling


def _settlement(flaw: str, walk_inputs: WalkInputs, criterion: Criterion) -> Settlement | None:
    return walk_inputs.settlements_by_flaw.get((flaw, criterion))
