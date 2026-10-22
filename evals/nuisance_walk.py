"""The nuisance population drawn from the holdout walk of evals/holdout_census.json.

The nuisance suite reaches every flaw the holdout walk reached, whatever its outcome, groups
the flaws by server (the rule's unit), and keeps a server when at least one of its census flaws
sets the version: in a graded class, reached through tools, its effect visible in a tool
response, and pinnable. Pure reads of the census and its draw settlements, no LLM, no network.
"""

import re
from dataclasses import dataclass
from enum import StrEnum

from evals.census_classification import Classification, Criterion, Primitive, in_grammar
from evals.census_draw import Settlement
from evals.cve_targets import CVE_TARGETS
from evals.holdout_census import CLASSIFIERS, HoldoutCensus
from evals.holdout_exclusions import BENCHMARK_FLAWS, EXCLUDED_SERVERS


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


def reached_identifiers(census: HoldoutCensus) -> list[str]:
    if census.draw is None:
        raise ValueError("the census has no draw walk to follow")
    return [step.identifier for step in census.draw.walk]


def normalized_package(server_package: str) -> str:
    prefix = "PyPI:"
    if not server_package.startswith(prefix):
        return server_package
    name = server_package[len(prefix) :]
    return prefix + re.sub(r"[-_.]+", "-", name).lower()


def server_of(identifier: str, census: HoldoutCensus) -> str:
    for classification in census.classifications[CLASSIFIERS[0]]:
        if classification.flaw == identifier:
            return normalized_package(classification.server_package)
    raise ValueError(f"no classification for flaw {identifier}")


def census_flaws_of(server_package: str, census: HoldoutCensus) -> list[str]:
    return [
        flaw.identifier
        for flaw in census.flaws
        if server_of(flaw.identifier, census) == server_package
    ]


def version_setting_flaws(server_package: str, census: HoldoutCensus) -> list[str]:
    return [flaw for flaw in census_flaws_of(server_package, census) if _sets_version(flaw, census)]


def acceptance_servers(census: HoldoutCensus) -> set[str]:
    """Every benchmark flaw's server, the dropped targets' included."""
    return {server_of(flaw, census) for flaw in BENCHMARK_FLAWS if flaw in _classified(census)}


def current_acceptance_servers(census: HoldoutCensus) -> set[str]:
    classified = _classified(census)
    return {server_of(t.cve_id, census) for t in CVE_TARGETS if t.cve_id in classified}


def _classified(census: HoldoutCensus) -> set[str]:
    return {classification.flaw for classification in census.classifications[CLASSIFIERS[0]]}


def nuisance_population(census: HoldoutCensus) -> list[NuisanceServer]:
    acceptance = acceptance_servers(census)
    excluded = {normalized_package(package) for package in EXCLUDED_SERVERS}
    population: list[NuisanceServer] = []
    seen: set[str] = set()
    for identifier in reached_identifiers(census):
        server = server_of(identifier, census)
        if server in seen:
            continue
        seen.add(server)
        version_setting = version_setting_flaws(server, census)
        if not version_setting:
            continue
        population.append(
            NuisanceServer(
                server_package=server,
                reaching_flaw=identifier,
                flaws=tuple(census_flaws_of(server, census)),
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


def _sets_version(flaw: str, census: HoldoutCensus) -> bool:
    seen = _classifications_of(flaw, census)
    return (
        _met(flaw, census, Criterion.GRAMMAR_CLASS, any(in_grammar(c.effect_class) for c in seen))
        and _met(
            flaw,
            census,
            Criterion.EFFECT_IN_TOOL_RESPONSE,
            any(c.effect_in_tool_response for c in seen),
        )
        and _met(flaw, census, Criterion.PINNABLE, any(c.pinnable for c in seen))
        and _tools_reached(flaw, census, seen)
    )


def _met(flaw: str, census: HoldoutCensus, criterion: Criterion, from_classifiers: bool) -> bool:
    settlement = _settlement(flaw, census, criterion)
    if settlement is not None:
        return settlement.verdict
    return from_classifiers


def _tools_reached(flaw: str, census: HoldoutCensus, seen: list[Classification]) -> bool:
    if any(c.primitive == Primitive.TOOLS for c in seen):
        return True
    # A False STDIO_TOOLS_CALL settlement does not override: it may hold for the transport
    # alone (not stdio), and this suite counts a flaw whatever transport the census records.
    settlement = _settlement(flaw, census, Criterion.STDIO_TOOLS_CALL)
    return settlement is not None and settlement.verdict


def _settlement(flaw: str, census: HoldoutCensus, criterion: Criterion) -> Settlement | None:
    if census.draw is None:
        return None
    for settlement in census.draw.settlements:
        if settlement.flaw == flaw and settlement.criterion == criterion:
            return settlement
    return None


def _classifications_of(flaw: str, census: HoldoutCensus) -> list[Classification]:
    return [
        classification
        for own in census.classifications.values()
        for classification in own
        if classification.flaw == flaw
    ]
