import json
from collections.abc import Callable
from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_admission_given as given
from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.nuisance_admission import NuisanceAdmission, load_admission

_MUTATIONS: list[tuple[Callable[[NuisanceAdmission], NuisanceAdmission], str]] = [
    (given.with_a_stale_grammar_fingerprint, "grammar fingerprint"),
    (given.with_an_unsettled_disagreement, "has no settlement"),
    (given.with_a_flaw_of_another_server, "is not a census flaw"),
    (given.with_no_counted_tool, "no counted tool"),
    (given.with_a_server_patched_version_of_no_flaw, "is not a counted flaw's patched version"),
    (
        given.with_a_server_patched_surfaces_set_on_the_servers_own_version,
        "sets server_patched_surfaces on the server's own patched version",
    ),
    (given.with_an_acceptance_service, "is an acceptance service"),
    (given.with_an_inconsistent_tool_record, "renames 'read_file' to 'write_file'"),
    (given.with_a_counted_tool_missing_its_benign_call, "has no benign call"),
    (given.with_an_unknown_backend_provisioner, "is not registered"),
    (given.with_a_backend_fixture_differing_from_its_provisioner, "fake/backend:1.0"),
    (given.with_a_networked_host_and_no_backend, "has_network without a backend"),
]


def test_the_clean_admission_has_no_problems():
    admission = given.an_admission()
    assert given.problems_of(admission) == []


@pytest.mark.parametrize(
    ("mutate", "fragment"),
    _MUTATIONS,
    ids=[mutate.__name__ for mutate, _ in _MUTATIONS],
)
def test_each_mutation_yields_exactly_one_problem_carrying_its_rule(
    mutate: Callable[[NuisanceAdmission], NuisanceAdmission], fragment: str
):
    [problem] = given.problems_of(mutate(given.an_admission()))

    assert fragment in problem


def test_a_registered_backend_fixture_has_no_problem():
    admission = given.with_a_registered_backend(given.an_admission())

    assert given.problems_of(admission) == []


def test_a_networked_host_with_no_backend_is_refused():
    admission = given.with_a_networked_host_and_no_backend(given.an_admission())

    problems = given.problems_of(admission)

    assert problems == [
        f"{given.SERVER_PACKAGE}: has_network without a backend: "
        "a server with no backend runs with no network"
    ]


def test_a_fixture_backend_need_with_no_backend_is_allowed():
    admission = given.with_every_flaw_needing_the_fixture(given.an_admission())

    assert given.problems_of(admission) == []


def test_a_flaw_recorded_under_another_package_is_foreign_without_a_settlement():
    census = given.a_nuisance_census_with_the_second_flaw_under_another_package()

    problems = given.problems_of(given.an_admission(), census)

    assert any(given.SECOND_FLAW in problem and "census flaw" in problem for problem in problems)


def test_a_server_package_settlement_unifies_the_foreign_flaw():
    census = given.a_nuisance_census_with_the_second_flaw_under_another_package()
    admission = given.with_the_second_flaw_settled_here(given.an_admission())

    assert given.problems_of(admission, census) == []


def test_load_admission_returns_the_written_clean_admission(tmp_path: Path):
    admission = given.an_admission()
    path = given.written(tmp_path, admission)

    assert load_admission(path, given.a_nuisance_census()) == admission


def test_load_admission_reads_the_host_as_a_planting_host(tmp_path: Path):
    path = given.written(tmp_path, given.an_admission())

    [server] = load_admission(path, given.a_nuisance_census()).servers

    assert server.host == PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)


def test_load_admission_refuses_a_server_without_a_host(tmp_path: Path):
    path = given.written(tmp_path, given.an_admission())
    document = json.loads(path.read_text())
    del document["servers"][0]["host"]
    path.write_text(json.dumps(document))

    with pytest.raises(ValueError):
        load_admission(path, given.a_nuisance_census())


def test_load_admission_on_a_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_admission(tmp_path / "absent.json", given.a_nuisance_census())


def test_load_admission_on_a_mutated_admission_raises_with_the_problem(tmp_path: Path):
    path = given.written(tmp_path, given.with_a_flaw_of_another_server(given.an_admission()))

    with pytest.raises(ValueError, match="is not a census flaw"):
        load_admission(path, given.a_nuisance_census())
