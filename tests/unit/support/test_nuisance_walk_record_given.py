import tests.unit.support.test_nuisance_walk_given as walk_given
from evals.cve.census.census import Census
from evals.cve.census.classification import Criterion
from evals.cve.detection.draw_record import Settlement
from evals.cve.nuisance.walk_record import (
    IdentitySettlement,
    NuisanceWalkRecord,
    WalkInputs,
)


def a_census() -> Census:
    """`walked` is reached by the detection walk, `queued` is a draw-order flaw past it, and
    `unpinnable` is a census flaw outside the draw order."""
    return walk_given.a_census_walking(
        [("walked", "drawn", "npm:srv1")],
        queued={"server_package": "npm:srv2"},
        unpinnable={"server_package": "npm:srv3", **walk_given.NOT_PINNABLE},
    )


def a_census_settling(flaw: str, criterion: Criterion, ruling: bool) -> Census:
    return walk_given.with_a_settlement(a_census(), flaw, criterion, ruling)


def a_census_split_on_the_effect_of(flaw: str) -> Census:
    """The second classifier finds the flaw's effect hidden, the first finds it shown."""
    return walk_given.with_the_second_classifier_overriding(
        a_census(), flaw, walk_given.EFFECT_HIDDEN
    )


def a_census_split_on_the_grammar_class_of(flaw: str) -> Census:
    """The second classifier files the flaw outside the grammar, the first inside."""
    return walk_given.with_the_second_classifier_overriding(
        a_census(), flaw, walk_given.OUTSIDE_THE_GRAMMAR
    )


def a_census_naming_two_packages_for_the_queue() -> Census:
    return walk_given.with_the_second_classifier_overriding(
        a_census(), "queued", {"server_package": "https://github.com/acme/srv2"}
    )


an_empty_record = walk_given.an_empty_record


def a_record_settling(*settlements: tuple[str, Criterion, bool]) -> NuisanceWalkRecord:
    return an_empty_record().model_copy(
        update={
            "settlements": [
                Settlement(flaw=flaw, criterion=criterion, ruling=ruling, reason="read")
                for flaw, criterion, ruling in settlements
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


def paired(census: Census, record: NuisanceWalkRecord) -> WalkInputs:
    return WalkInputs(census=census, record=record)


written = walk_given.written_record
