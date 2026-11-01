import tests.unit.support.test_nuisance_walk_given as walk_given
from evals.census_classification import Criterion
from evals.census_draw import Settlement
from evals.holdout_census import HoldoutCensus
from evals.nuisance_walk_record import (
    IdentitySettlement,
    NuisanceCensus,
    NuisanceWalkRecord,
)


def a_census() -> HoldoutCensus:
    """`walked` is reached by the holdout walk, `queued` is a draw-order flaw past it, and
    `unpinnable` is a census flaw outside the draw order."""
    return walk_given.a_census_walking(
        [("walked", "drawn", "npm:srv1")],
        queued={"server_package": "npm:srv2"},
        unpinnable={"server_package": "npm:srv3", **walk_given.NOT_PINNABLE},
    )


def a_census_settling(flaw: str, criterion: Criterion, verdict: bool) -> HoldoutCensus:
    return walk_given.with_a_settlement(a_census(), flaw, criterion, verdict)


def a_census_split_on_the_effect_of(flaw: str) -> HoldoutCensus:
    """The second classifier finds the flaw's effect hidden, the first finds it shown."""
    return walk_given.with_the_second_classifier_overriding(
        a_census(), flaw, walk_given.EFFECT_HIDDEN
    )


def a_census_naming_two_packages_for_the_queue() -> HoldoutCensus:
    return walk_given.with_the_second_classifier_overriding(
        a_census(), "queued", {"server_package": "https://github.com/acme/srv2"}
    )


an_empty_record = walk_given.an_empty_record


def a_record_settling(*settlements: tuple[str, Criterion, bool]) -> NuisanceWalkRecord:
    return an_empty_record().model_copy(
        update={
            "settlements": [
                Settlement(flaw=flaw, criterion=criterion, verdict=verdict, reason="read")
                for flaw, criterion, verdict in settlements
            ]
        }
    )


def a_record_identifying(*flaws: str) -> NuisanceWalkRecord:
    return an_empty_record().model_copy(
        update={
            "identities": [
                IdentitySettlement(flaw=flaw, server_package="npm:srv2", reason="read")
                for flaw in flaws
            ]
        }
    )


def paired(census: HoldoutCensus, record: NuisanceWalkRecord) -> NuisanceCensus:
    return NuisanceCensus(census=census, record=record)


written = walk_given.written_record
