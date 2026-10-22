from datetime import date
from pathlib import Path
from typing import Any, Literal

import tests.unit.support.test_census_figures_given as figures
import tests.unit.support.test_census_grouping_given as grouping
import tests.unit.support.test_holdout_census_given as census_given
from evals.census_classification import Criterion, Primitive, Transport
from evals.census_draw import DrawRecord, DrawWalkStep, Settlement
from evals.census_sources import SourceName, SourceRecord
from evals.holdout_census import CLASSIFIERS, CensusFlaw, Discovery, HoldoutCensus

Outcome = Literal["drawn", "skipped", "given_up", "excluded"]

OUTSIDE_THE_GRAMMAR: dict[str, Any] = grouping.OUTSIDE_THE_GRAMMAR
NOT_PINNABLE: dict[str, Any] = grouping.NOT_PINNABLE
EFFECT_HIDDEN: dict[str, Any] = {"effect_in_tool_response": False}
ON_RESOURCES: dict[str, Any] = {"primitive": Primitive.RESOURCES}
OVER_HTTP: dict[str, Any] = {"transport": Transport.HTTP}


def a_census_walking(
    steps: list[tuple[str, Outcome, str]], **classification_overrides_per_flaw: dict[str, Any]
) -> HoldoutCensus:
    """A census built around a draw walk of mixed outcomes. Each step is (identifier, outcome,
    server_package). A flaw named only in the overrides (not in the walk) still becomes a census
    flaw, so a server's non-walk census flaws can be carried; its server_package comes from the
    override. nuisance_walk reads draw.walk, draw.settlements and classifications only, so the
    census needs no derived part and is never validated through load_census.
    """
    step_package: dict[str, str] = {}
    order: list[str] = []
    for identifier, _outcome, package in steps:
        if identifier not in step_package:
            order.append(identifier)
        step_package[identifier] = package
    for identifier in classification_overrides_per_flaw:
        if identifier not in step_package:
            order.append(identifier)

    classifications = {
        classifier: [
            figures.a_classification(
                **{
                    "flaw": identifier,
                    "server_package": step_package.get(identifier, ""),
                    **classification_overrides_per_flaw.get(identifier, {}),
                }
            )
            for identifier in order
        ]
        for classifier in CLASSIFIERS
    }
    draw = DrawRecord(
        rule_commit="abc1234",
        grammar_fingerprint="deadbeef",
        settlements=[],
        walk=[
            DrawWalkStep(identifier=identifier, outcome=outcome, reason="")
            for identifier, outcome, _package in steps
        ],
        cards=[],
        card_checks=[],
        give_ups=[],
        drawn=[],
    )
    return _bare_census(order).model_copy(update={"classifications": classifications, "draw": draw})


def with_the_second_classifier_overriding(
    census: HoldoutCensus, flaw: str, override: dict[str, Any]
) -> HoldoutCensus:
    """Override the second classifier's classification of one flaw, so a disagreement between the
    two classifiers can be exercised (server_of reads the first, the criteria read either)."""
    second = CLASSIFIERS[1]
    updated = [
        each.model_copy(update=override) if each.flaw == flaw else each
        for each in census.classifications[second]
    ]
    classifications = census.classifications | {second: updated}
    return census.model_copy(update={"classifications": classifications})


def with_a_settlement(
    census: HoldoutCensus, flaw: str, criterion: Criterion, verdict: bool
) -> HoldoutCensus:
    assert census.draw is not None
    settlement = Settlement(
        flaw=flaw, criterion=criterion, verdict=verdict, reason="the maintainer"
    )
    draw = census.draw.model_copy(update={"settlements": [*census.draw.settlements, settlement]})
    return census.model_copy(update={"draw": draw})


def written(tmp_path: Path, census: HoldoutCensus) -> Path:
    return census_given.written(tmp_path, census)


def _bare_census(identifiers: list[str]) -> HoldoutCensus:
    census = census_given.a_census()
    return census.model_copy(update={"flaws": [_flaw(identifier) for identifier in identifiers]})


def _flaw(identifier: str) -> CensusFlaw:
    record = SourceRecord(
        source=SourceName.NVD,
        id=identifier,
        published=date(2025, 6, 10),
        withdrawn=None,
        rejected=False,
    )
    return CensusFlaw(
        identifier=identifier,
        no_census_identifier=False,
        ids=[identifier],
        records=[record],
        disclosure_date=date(2025, 6, 10),
        found_by=[Discovery.PREFILTER],
    )
