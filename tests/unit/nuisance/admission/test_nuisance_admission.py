import json
from collections.abc import Callable
from pathlib import Path

import pytest

import tests.unit.support.admission_mutations as mutations
import tests.unit.support.nuisance_admissions as admissions
from evals.cve.nuisance.admission.admission import NuisanceAdmission, load_admission
from evals.cve.planting_base import PlantingHost, SymbolicUser

_MUTATIONS: list[tuple[Callable[[NuisanceAdmission], NuisanceAdmission], str]] = [
    (mutations.with_a_stale_grammar_fingerprint, "grammar fingerprint"),
    (mutations.with_an_unsettled_disagreement, "has no settlement"),
    (mutations.with_a_flaw_of_another_server, "is not a census flaw"),
    (mutations.with_no_counted_tool, "no counted tool"),
    (mutations.with_a_server_patched_version_of_no_flaw, "is not a counted flaw's patched version"),
    (
        mutations.with_a_server_patched_surfaces_set_on_the_servers_own_version,
        "sets server_patched_surfaces on the server's own patched version",
    ),
    (mutations.with_an_acceptance_service, "is an acceptance service"),
    (mutations.with_an_inconsistent_tool_record, "renames 'read_file' to 'write_file'"),
    (mutations.with_a_counted_tool_missing_its_benign_call, "has no benign call"),
    (mutations.with_an_unknown_backend_provisioner, "is not registered"),
    (mutations.with_a_backend_fixture_differing_from_its_provisioner, "fake/backend:1.0"),
    (mutations.with_a_networked_host_and_no_backend, "has_network without a backend"),
    (mutations.with_a_trust_setting_and_no_stand_in, "a trust setting with no stand-in"),
]


def test_the_clean_admission_has_no_problems():
    admission = admissions.an_admission()
    assert admissions.problems_of(admission) == []


@pytest.mark.parametrize(
    ("mutate", "fragment"),
    _MUTATIONS,
    ids=[mutate.__name__ for mutate, _ in _MUTATIONS],
)
def test_each_mutation_yields_exactly_one_problem_carrying_its_rule(
    mutate: Callable[[NuisanceAdmission], NuisanceAdmission], fragment: str
):
    [problem] = admissions.problems_of(mutate(admissions.an_admission()))

    assert fragment in problem


def test_a_registered_backend_fixture_has_no_problem():
    admission = mutations.with_a_registered_backend(admissions.an_admission())

    assert admissions.problems_of(admission) == []


def test_a_networked_host_with_no_backend_is_refused():
    admission = mutations.with_a_networked_host_and_no_backend(admissions.an_admission())

    problems = admissions.problems_of(admission)

    assert problems == [
        f"{admissions.SERVER_PACKAGE}: has_network without a backend: "
        "a server with no backend runs with no network"
    ]


def test_a_fixture_backend_need_with_no_backend_is_allowed():
    admission = mutations.with_every_flaw_needing_the_fixture(admissions.an_admission())

    assert admissions.problems_of(admission) == []


def test_a_flaw_recorded_under_another_package_is_foreign_without_a_settlement():
    census = admissions.walk_inputs_with_the_second_flaw_under_another_package()

    problems = admissions.problems_of(admissions.an_admission(), census)

    assert any(
        admissions.SECOND_FLAW in problem and "census flaw" in problem for problem in problems
    )


def test_a_server_package_settlement_unifies_the_foreign_flaw():
    census = admissions.walk_inputs_with_the_second_flaw_under_another_package()
    admission = mutations.with_the_second_flaw_settled_here(admissions.an_admission())

    assert admissions.problems_of(admission, census) == []


def test_load_admission_returns_the_written_clean_admission(tmp_path: Path):
    admission = admissions.an_admission()
    path = admissions.written(tmp_path, admission)

    assert load_admission(path, admissions.walk_inputs_of()) == admission


def test_load_admission_reads_the_host_as_a_planting_host(tmp_path: Path):
    path = admissions.written(tmp_path, admissions.an_admission())

    [server] = load_admission(path, admissions.walk_inputs_of()).servers

    assert server.host == PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)


def test_load_admission_refuses_a_server_without_a_host(tmp_path: Path):
    path = admissions.written(tmp_path, admissions.an_admission())
    document = json.loads(path.read_text())
    del document["servers"][0]["host"]
    path.write_text(json.dumps(document))

    with pytest.raises(ValueError):
        load_admission(path, admissions.walk_inputs_of())


def test_load_admission_refuses_the_host_user(tmp_path: Path):
    path = admissions.written(tmp_path, admissions.an_admission())
    document = json.loads(path.read_text())
    document["servers"][0]["host"]["user"] = "host"
    path.write_text(json.dumps(document))

    with pytest.raises(ValueError):
        load_admission(path, admissions.walk_inputs_of())


def test_load_admission_on_a_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_admission(tmp_path / "absent.json", admissions.walk_inputs_of())


def test_load_admission_on_a_mutated_admission_raises_with_the_problem(tmp_path: Path):
    path = admissions.written(
        tmp_path, mutations.with_a_flaw_of_another_server(admissions.an_admission())
    )

    with pytest.raises(ValueError, match="is not a census flaw"):
        load_admission(path, admissions.walk_inputs_of())
