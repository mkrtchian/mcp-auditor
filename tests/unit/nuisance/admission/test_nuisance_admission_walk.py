"""The admission's agreement with the nuisance walk: the reaching flaw of each admitted server,
the addition's size, and the exits the admission records."""

import pytest

import tests.unit.nuisance.admission.support.test_nuisance_admission_given as admission_given
import tests.unit.nuisance.admission.support.test_nuisance_admission_walk_given as given
import tests.unit.nuisance.admission.support.test_nuisance_walk_given as walk_given
import tests.unit.support.test_nuisance_admission_edits_given as edits
from evals.cve.nuisance.admission.walk import nuisance_population
from evals.cve.nuisance.exits import EXIT_REASON_TEXTS, ExitReason
from tests.unit.support.admission_mutations import admitting


def test_an_admitted_server_the_walk_does_not_reach_is_refused():
    census = admission_given.walk_inputs_with_the_second_flaw_under_another_package()

    problems = admission_given.problems_of(
        given.admitting_another_package_outside_the_walk(), census
    )

    assert problems == [f"{admission_given.OTHER_PACKAGE}: not reached by the walk"]


def test_an_admitted_nuisance_acceptance_server_outside_the_walk_passes():
    census = walk_given.walk_inputs_of(admission_given.a_census_with_an_acceptance_server())

    assert (
        admission_given.problems_of(admission_given.admitting_the_acceptance_server(), census) == []
    )


def test_a_wrong_reaching_flaw_is_refused_naming_both_flaws():
    admission = given.with_the_second_flaw_reaching(admission_given.an_admission())

    [problem] = admission_given.problems_of(admission, admission_given.walk_inputs_of())

    assert admission_given.SERVER_PACKAGE in problem
    assert admission_given.FIRST_FLAW in problem
    assert admission_given.SECOND_FLAW in problem


def test_a_queue_server_past_the_addition_size_is_refused():
    census = given.walk_inputs_with_two_queue_servers(addition_size=1)
    first, second = given.the_queue_packages()

    [problem] = admission_given.problems_of(given.admitting_the_queue_servers(), census)

    assert second in problem
    assert first not in problem


def test_a_queue_server_with_a_standing_exit_does_not_count_toward_the_size():
    census = given.walk_inputs_with_two_queue_servers(addition_size=1)
    first, _ = given.the_queue_packages()
    admission = edits.without_stdio(given.admitting_the_queue_servers(), first)

    assert admission_given.problems_of(admission, census) == []


def test_queue_servers_within_the_addition_size_pass():
    census = given.walk_inputs_with_two_queue_servers(addition_size=2)

    assert admission_given.problems_of(given.admitting_the_queue_servers(), census) == []


def test_a_recorded_exit_for_a_listed_server_left_out_passes():
    admission = given.recording(admitting(), given.a_recorded_exit(admission_given.SERVER_PACKAGE))

    assert admission_given.problems_of(admission) == []


def test_a_recorded_exit_for_a_server_the_walk_does_not_reach_is_refused():
    admission = given.recording(admitting(), given.a_recorded_exit("npm:nowhere"))

    assert admission_given.problems_of(admission) == [
        "npm:nowhere: recorded exit for a server the walk does not reach"
    ]


def test_a_recorded_exit_for_a_server_whose_exit_the_walk_derives_is_refused():
    walk_inputs = walk_given.a_walk_reaching_a_server_with_no_flaw_that_may_count()
    admission = given.recording(admitting(), given.a_recorded_exit("npm:bad"))

    [problem] = admission_given.problems_of(admission, walk_inputs)

    assert problem.startswith("npm:bad: ")
    assert EXIT_REASON_TEXTS[ExitReason.NO_COUNTED_FLAW] in problem


def test_a_recorded_exit_for_a_server_the_walk_marks_is_refused_naming_the_mark():
    census = walk_given.a_census_walking([("exc1", "drawn", walk_given.AN_EXCLUDED_SERVER)])
    census = walk_given.with_the_second_classifier_overriding(
        census, "exc1", {"server_package": "npm:another-label"}
    )
    walk_inputs = walk_given.walk_inputs_of(census)
    [listed] = nuisance_population(walk_inputs)
    admission = given.recording(admitting(), given.a_recorded_exit(listed.server_package))

    [problem] = admission_given.problems_of(admission, walk_inputs)

    assert listed.server_package in problem
    assert EXIT_REASON_TEXTS[ExitReason.EXCLUDED_SERVER] in problem


def test_two_recorded_exits_for_one_server_are_refused():
    package = admission_given.SERVER_PACKAGE
    admission = given.recording(
        admitting(),
        given.a_recorded_exit(package),
        given.a_recorded_exit(package, ExitReason.NO_COUNTED_FLAW),
    )

    assert admission_given.problems_of(admission) == [f"{package}: 2 recorded exits"]


@pytest.mark.parametrize("reason", [ExitReason.NO_COUNTED_TOOL_LEFT, ExitReason.SPENT_BY_A_READING])
def test_a_server_admitted_and_recorded_out_is_refused(reason: ExitReason):
    admission = given.recording(
        admission_given.an_admission(),
        given.a_recorded_exit(admission_given.SERVER_PACKAGE, reason),
    )

    [problem] = admission_given.problems_of(admission)

    assert admission_given.SERVER_PACKAGE in problem
    assert EXIT_REASON_TEXTS[reason] in problem


def test_a_recorded_acceptance_target_reason_is_refused():
    package = admission_given.SERVER_PACKAGE
    admission = given.recording(
        admitting(),
        given.a_recorded_exit(package, ExitReason.ACCEPTANCE_TARGET_SERVER),
    )

    reason = EXIT_REASON_TEXTS[ExitReason.ACCEPTANCE_TARGET_SERVER]
    assert admission_given.problems_of(admission) == [
        f"{package}: recorded exit for the reason '{reason}', which only the walk derives"
    ]
