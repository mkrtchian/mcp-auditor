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

from dataclasses import dataclass
from enum import StrEnum

from evals.cve.census.census import CLASSIFIERS, Census
from evals.cve.census.classification import (
    Classification,
    Criterion,
    Primitive,
    criteria_met,
)
from evals.cve.census.draw_order import draw_order
from evals.cve.census.exclusions import ACCEPTANCE_TARGET_FLAWS, EXCLUDED_SERVERS
from evals.cve.census.grouping import DRAW_ORDER_CRITERIA
from evals.cve.detection.draw_record import Settlement
from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.cve.nuisance.walk_record import (
    WalkInputs,
    normalized_package,
    reached_identifiers,
)


class ServerMark(StrEnum):
    EXCLUDED = "excluded"
    ACCEPTANCE_TARGET_SERVER = "acceptance_target_server"


@dataclass(frozen=True)
class NuisanceServer:
    server_package: str
    reaching_flaw: str
    reaching_position: int
    in_addition: bool
    flaws: tuple[str, ...]
    candidate_counted_flaws: tuple[str, ...]
    mark: ServerMark | None


def server_of(identifier: str, walk_inputs: WalkInputs) -> str:
    server = walk_inputs.server_by_flaw.get(identifier)
    if server is None:
        raise ValueError(f"no classification for flaw {identifier}")
    return server


def census_flaws_of(server_package: str, walk_inputs: WalkInputs) -> list[str]:
    return [
        flaw.identifier
        for flaw in walk_inputs.census.flaws
        if server_of(flaw.identifier, walk_inputs) == server_package
    ]


def candidate_counted_flaws(server_package: str, walk_inputs: WalkInputs) -> list[str]:
    return [
        flaw
        for flaw in census_flaws_of(server_package, walk_inputs)
        if _may_count(flaw, walk_inputs)
    ]


def acceptance_target_servers(walk_inputs: WalkInputs) -> set[str]:
    """Every benchmark flaw's server, the dropped targets' included."""
    classified = _classified(walk_inputs.census)
    return {server_of(flaw, walk_inputs) for flaw in ACCEPTANCE_TARGET_FLAWS if flaw in classified}


def nuisance_acceptance_servers(walk_inputs: WalkInputs) -> set[str]:
    classified = _classified(walk_inputs.census)
    return {
        server_of(t.flaw_id, walk_inputs) for t in ACCEPTANCE_TARGETS if t.flaw_id in classified
    }


def _classified(census: Census) -> set[str]:
    return {classification.flaw for classification in census.classifications[CLASSIFIERS[0]]}


def nuisance_population(walk_inputs: WalkInputs) -> list[NuisanceServer]:
    acceptance = acceptance_target_servers(walk_inputs)
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
                mark=_mark(server, acceptance, excluded),
            )
        )
    return population


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
    holdout = reached_identifiers(walk_inputs.census)
    for identifier in holdout:
        if identifier not in positions:
            raise ValueError(f"the detection walk reaches {identifier}, outside the draw order")
    reached = set(holdout)
    queue = [
        identifier
        for identifier in order
        if identifier not in reached and _meets_draw_criteria(identifier, walk_inputs)
    ]
    return [
        *(_Reach(identifier, positions[identifier], False) for identifier in holdout),
        *(_Reach(identifier, positions[identifier], True) for identifier in queue),
    ]


def _meets_draw_criteria(flaw: str, walk_inputs: WalkInputs) -> bool:
    seen = walk_inputs.classifications_by_flaw.get(flaw, [])
    return all(
        _met(flaw, walk_inputs, criterion, any(criteria_met(c)[criterion] for c in seen))
        for criterion in DRAW_ORDER_CRITERIA
    )


def _mark(server: str, acceptance: set[str], excluded: set[str]) -> ServerMark | None:
    if server in acceptance:
        return ServerMark.ACCEPTANCE_TARGET_SERVER
    if server in excluded:
        return ServerMark.EXCLUDED
    return None


def _may_count(flaw: str, walk_inputs: WalkInputs) -> bool:
    seen = walk_inputs.classifications_by_flaw.get(flaw, [])
    return (
        _met(
            flaw,
            walk_inputs,
            Criterion.EFFECT_IN_TOOL_RESPONSE,
            any(c.effect_in_tool_response for c in seen),
        )
        and _met(flaw, walk_inputs, Criterion.PINNABLE, any(c.pinnable for c in seen))
        and _tools_reached(flaw, walk_inputs, seen)
    )


def _met(flaw: str, walk_inputs: WalkInputs, criterion: Criterion, from_classifiers: bool) -> bool:
    settlement = _settlement(flaw, walk_inputs, criterion)
    if settlement is not None:
        return settlement.ruling
    return from_classifiers


def _tools_reached(flaw: str, walk_inputs: WalkInputs, seen: list[Classification]) -> bool:
    if any(c.primitive == Primitive.TOOLS for c in seen):
        return True
    # A False STDIO_TOOLS_CALL settlement does not override: it may hold for the transport
    # alone (not stdio), and this suite counts a flaw whatever transport the census records.
    settlement = _settlement(flaw, walk_inputs, Criterion.STDIO_TOOLS_CALL)
    return settlement is not None and settlement.ruling


def _settlement(flaw: str, walk_inputs: WalkInputs, criterion: Criterion) -> Settlement | None:
    return walk_inputs.settlements_by_flaw.get((flaw, criterion))
