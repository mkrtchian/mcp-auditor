"""The nuisance population drawn from the holdout walk of evals/holdout_census.json.

The nuisance suite reaches every flaw the holdout walk reached, whatever its outcome, groups
the flaws by server (the rule's unit), and keeps a server when at least one of its census flaws
sets the version: in a graded class, reached through tools, its effect visible in a tool
response, and pinnable. Pure reads of the census and its draw settlements, no LLM, no network.
"""

from dataclasses import dataclass
from enum import StrEnum

from evals.census_classification import Classification, Criterion, Primitive, in_grammar
from evals.census_draw import Settlement
from evals.cve_targets import CVE_TARGETS
from evals.holdout_census import CLASSIFIERS, HoldoutCensus
from evals.holdout_exclusions import BENCHMARK_FLAWS, EXCLUDED_SERVERS
from evals.nuisance_walk_record import NuisanceCensus, normalized_package, reached_identifiers


class ServerMark(StrEnum):
    EXCLUDED = "excluded"
    ACCEPTANCE = "acceptance"


@dataclass(frozen=True)
class NuisanceServer:
    server_package: str
    reaching_flaw: str
    flaws: tuple[str, ...]
    version_setting: tuple[str, ...]
    mark: ServerMark | None


def server_of(identifier: str, nuisance_census: NuisanceCensus) -> str:
    for classification in nuisance_census.census.classifications[CLASSIFIERS[0]]:
        if classification.flaw == identifier:
            return normalized_package(classification.server_package)
    raise ValueError(f"no classification for flaw {identifier}")


def census_flaws_of(server_package: str, nuisance_census: NuisanceCensus) -> list[str]:
    return [
        flaw.identifier
        for flaw in nuisance_census.census.flaws
        if server_of(flaw.identifier, nuisance_census) == server_package
    ]


def version_setting_flaws(server_package: str, nuisance_census: NuisanceCensus) -> list[str]:
    return [
        flaw
        for flaw in census_flaws_of(server_package, nuisance_census)
        if _sets_version(flaw, nuisance_census)
    ]


def acceptance_servers(nuisance_census: NuisanceCensus) -> set[str]:
    """Every benchmark flaw's server, the dropped targets' included."""
    classified = _classified(nuisance_census.census)
    return {server_of(flaw, nuisance_census) for flaw in BENCHMARK_FLAWS if flaw in classified}


def current_acceptance_servers(nuisance_census: NuisanceCensus) -> set[str]:
    classified = _classified(nuisance_census.census)
    return {server_of(t.cve_id, nuisance_census) for t in CVE_TARGETS if t.cve_id in classified}


def _classified(census: HoldoutCensus) -> set[str]:
    return {classification.flaw for classification in census.classifications[CLASSIFIERS[0]]}


def nuisance_population(nuisance_census: NuisanceCensus) -> list[NuisanceServer]:
    acceptance = acceptance_servers(nuisance_census)
    excluded = {normalized_package(package) for package in EXCLUDED_SERVERS}
    population: list[NuisanceServer] = []
    seen: set[str] = set()
    for identifier in reached_identifiers(nuisance_census.census):
        server = server_of(identifier, nuisance_census)
        if server in seen:
            continue
        seen.add(server)
        version_setting = version_setting_flaws(server, nuisance_census)
        if not version_setting:
            continue
        population.append(
            NuisanceServer(
                server_package=server,
                reaching_flaw=identifier,
                flaws=tuple(census_flaws_of(server, nuisance_census)),
                version_setting=tuple(version_setting),
                mark=_mark(server, acceptance, excluded),
            )
        )
    return population


def _mark(server: str, acceptance: set[str], excluded: set[str]) -> ServerMark | None:
    if server in acceptance:
        return ServerMark.ACCEPTANCE
    if server in excluded:
        return ServerMark.EXCLUDED
    return None


def _sets_version(flaw: str, nuisance_census: NuisanceCensus) -> bool:
    seen = _classifications_of(flaw, nuisance_census)
    return (
        _met(
            flaw,
            nuisance_census,
            Criterion.GRAMMAR_CLASS,
            any(in_grammar(c.effect_class) for c in seen),
        )
        and _met(
            flaw,
            nuisance_census,
            Criterion.EFFECT_IN_TOOL_RESPONSE,
            any(c.effect_in_tool_response for c in seen),
        )
        and _met(flaw, nuisance_census, Criterion.PINNABLE, any(c.pinnable for c in seen))
        and _tools_reached(flaw, nuisance_census, seen)
    )


def _met(
    flaw: str, nuisance_census: NuisanceCensus, criterion: Criterion, from_classifiers: bool
) -> bool:
    settlement = _settlement(flaw, nuisance_census, criterion)
    if settlement is not None:
        return settlement.verdict
    return from_classifiers


def _tools_reached(flaw: str, nuisance_census: NuisanceCensus, seen: list[Classification]) -> bool:
    if any(c.primitive == Primitive.TOOLS for c in seen):
        return True
    # A False STDIO_TOOLS_CALL settlement does not override: it may hold for the transport
    # alone (not stdio), and this suite counts a flaw whatever transport the census records.
    settlement = _settlement(flaw, nuisance_census, Criterion.STDIO_TOOLS_CALL)
    return settlement is not None and settlement.verdict


def _settlement(
    flaw: str, nuisance_census: NuisanceCensus, criterion: Criterion
) -> Settlement | None:
    draw = nuisance_census.census.draw
    if draw is None:
        return None
    for settlement in draw.settlements:
        if settlement.flaw == flaw and settlement.criterion == criterion:
            return settlement
    return None


def _classifications_of(flaw: str, nuisance_census: NuisanceCensus) -> list[Classification]:
    return [
        classification
        for own in nuisance_census.census.classifications.values()
        for classification in own
        if classification.flaw == flaw
    ]
