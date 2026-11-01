"""The admission's agreement with the nuisance walk: the reaching flaw of each admitted server
and the addition's size."""

import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_admission_walk_given as given
import tests.unit.support.test_nuisance_walk_given as walk_given
from evals import cve_baseline
from evals.nuisance_admission import NuisanceAdmission, admission_problems
from evals.nuisance_walk_record import NuisanceCensus


def _problems(admission: NuisanceAdmission, census: NuisanceCensus) -> list[str]:
    return admission_problems(
        admission, census, cve_baseline.grammar_fingerprint(), admission_given.a_backend_registry()
    )


def test_an_admitted_server_the_walk_does_not_reach_is_refused():
    census = admission_given.a_nuisance_census_with_the_second_flaw_under_another_package()

    problems = _problems(given.admitting_another_package_outside_the_walk(), census)

    assert problems == [f"{admission_given.OTHER_PACKAGE}: not reached by the walk"]


def test_an_admitted_acceptance_server_outside_the_walk_passes():
    census = walk_given.a_nuisance_census(admission_given.a_census_with_an_acceptance_server())

    assert _problems(admission_given.admitting_the_acceptance_server(), census) == []


def test_a_wrong_reaching_flaw_is_refused_naming_both_flaws():
    admission = given.with_the_second_flaw_reaching(admission_given.an_admission())

    [problem] = _problems(admission, admission_given.a_nuisance_census())

    assert admission_given.SERVER_PACKAGE in problem
    assert admission_given.FIRST_FLAW in problem
    assert admission_given.SECOND_FLAW in problem


def test_a_queue_server_past_the_addition_size_is_refused():
    census = given.a_nuisance_census_with_two_queue_servers(addition_size=1)
    first, second = given.the_queue_packages()

    [problem] = _problems(given.admitting_the_queue_servers(), census)

    assert second in problem
    assert first not in problem


def test_a_queue_server_with_a_standing_exit_does_not_count_toward_the_size():
    census = given.a_nuisance_census_with_two_queue_servers(addition_size=1)
    first, _ = given.the_queue_packages()
    admission = given.without_stdio(given.admitting_the_queue_servers(), first)

    assert _problems(admission, census) == []


def test_queue_servers_within_the_addition_size_pass():
    census = given.a_nuisance_census_with_two_queue_servers(addition_size=2)

    assert _problems(given.admitting_the_queue_servers(), census) == []
