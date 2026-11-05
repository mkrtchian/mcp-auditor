"""The admission's agreement with the nuisance walk: the reaching flaw of each admitted server
and the addition's size."""

import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_admission_walk_given as given
import tests.unit.support.test_nuisance_walk_given as walk_given


def test_an_admitted_server_the_walk_does_not_reach_is_refused():
    census = admission_given.a_nuisance_census_with_the_second_flaw_under_another_package()

    problems = admission_given.problems_of(
        given.admitting_another_package_outside_the_walk(), census
    )

    assert problems == [f"{admission_given.OTHER_PACKAGE}: not reached by the walk"]


def test_an_admitted_acceptance_server_outside_the_walk_passes():
    census = walk_given.a_nuisance_census(admission_given.a_census_with_an_acceptance_server())

    assert (
        admission_given.problems_of(admission_given.admitting_the_acceptance_server(), census) == []
    )


def test_a_wrong_reaching_flaw_is_refused_naming_both_flaws():
    admission = given.with_the_second_flaw_reaching(admission_given.an_admission())

    [problem] = admission_given.problems_of(admission, admission_given.a_nuisance_census())

    assert admission_given.SERVER_PACKAGE in problem
    assert admission_given.FIRST_FLAW in problem
    assert admission_given.SECOND_FLAW in problem


def test_a_queue_server_past_the_addition_size_is_refused():
    census = given.a_nuisance_census_with_two_queue_servers(addition_size=1)
    first, second = given.the_queue_packages()

    [problem] = admission_given.problems_of(given.admitting_the_queue_servers(), census)

    assert second in problem
    assert first not in problem


def test_a_queue_server_with_a_standing_exit_does_not_count_toward_the_size():
    census = given.a_nuisance_census_with_two_queue_servers(addition_size=1)
    first, _ = given.the_queue_packages()
    admission = edits.without_stdio(given.admitting_the_queue_servers(), first)

    assert admission_given.problems_of(admission, census) == []


def test_queue_servers_within_the_addition_size_pass():
    census = given.a_nuisance_census_with_two_queue_servers(addition_size=2)

    assert admission_given.problems_of(given.admitting_the_queue_servers(), census) == []
