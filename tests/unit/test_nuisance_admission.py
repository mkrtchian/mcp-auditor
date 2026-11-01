import json
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

import tests.unit.support.test_nuisance_admission_given as given
import tests.unit.support.test_nuisance_walk_given as walk_given
from evals import cve_baseline
from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.nuisance_admission import (
    FlawRecord,
    NuisanceAdmission,
    admission_problems,
    load_admission,
)
from evals.nuisance_walk_record import NuisanceCensus

_MUTATORS: list[Callable[[NuisanceAdmission], NuisanceAdmission]] = [
    given.with_a_stale_grammar_fingerprint,
    given.with_an_unsettled_disagreement,
    given.with_a_flaw_of_another_server,
    given.with_no_counted_tool,
    given.with_a_server_patched_version_of_no_flaw,
    given.with_a_server_patched_surfaces_set_on_the_servers_own_version,
    given.with_an_acceptance_service,
    given.with_an_inconsistent_tool_record,
    given.with_a_counted_tool_missing_its_benign_call,
    given.with_an_unknown_backend_provisioner,
    given.with_a_backend_fixture_differing_from_its_provisioner,
]


def test_a_non_grammar_effect_class_is_refused_by_the_schema():
    with pytest.raises(ValidationError):
        FlawRecord(
            flaw="CVE-2025-0001",
            tools=[given.a_tool("read", "read", "unchanged")],
            effect_class="authorization_bypass",  # type: ignore[arg-type]
            patched_version="1.2.0",
            patched_source="advisory",
            launch_option=None,
            benign_calls=[],
            backend_need="none",
            declared_function_is_effect=False,
            fix_check=given.a_passing_fix_check(),
        )


def test_the_clean_admission_has_no_problems():
    admission = given.an_admission()
    assert (
        admission_problems(
            admission,
            given.a_nuisance_census(),
            cve_baseline.grammar_fingerprint(),
            given.a_backend_registry(),
        )
        == []
    )


@pytest.mark.parametrize("mutate", _MUTATORS)
def test_each_mutation_yields_exactly_one_problem(
    mutate: Callable[[NuisanceAdmission], NuisanceAdmission],
):
    admission = mutate(given.an_admission())

    problems = admission_problems(
        admission,
        given.a_nuisance_census(),
        cve_baseline.grammar_fingerprint(),
        given.a_backend_registry(),
    )

    assert len(problems) == 1, problems
    # The problem names the thing it is about: the server, or the grammar for the fingerprint.
    assert given.SERVER_PACKAGE in problems[0] or "grammar fingerprint" in problems[0]


def test_a_registered_backend_fixture_has_no_problem():
    admission = given.with_a_registered_backend(given.an_admission())

    assert (
        admission_problems(
            admission,
            given.a_nuisance_census(),
            cve_baseline.grammar_fingerprint(),
            given.a_backend_registry(),
        )
        == []
    )


def test_a_differing_backend_fixture_names_the_expected_one():
    admission = given.with_a_backend_fixture_differing_from_its_provisioner(given.an_admission())

    [problem] = admission_problems(
        admission,
        given.a_nuisance_census(),
        cve_baseline.grammar_fingerprint(),
        given.a_backend_registry(),
    )

    assert "fake/backend:1.0" in problem


def test_a_fixture_backend_need_with_no_backend_is_allowed():
    admission = given.with_every_flaw_needing_the_fixture(given.an_admission())

    assert (
        admission_problems(
            admission,
            given.a_nuisance_census(),
            cve_baseline.grammar_fingerprint(),
            given.a_backend_registry(),
        )
        == []
    )


def test_a_flaw_recorded_under_another_package_is_foreign_without_a_settlement():
    census = given.a_nuisance_census_with_the_second_flaw_under_another_package()

    problems = admission_problems(
        given.an_admission(), census, cve_baseline.grammar_fingerprint(), given.a_backend_registry()
    )

    assert any(given.SECOND_FLAW in problem and "census flaw" in problem for problem in problems)


def test_a_server_package_settlement_unifies_the_foreign_flaw():
    census = given.a_nuisance_census_with_the_second_flaw_under_another_package()
    admission = given.with_the_second_flaw_settled_here(given.an_admission())

    assert (
        admission_problems(
            admission, census, cve_baseline.grammar_fingerprint(), given.a_backend_registry()
        )
        == []
    )


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


def test_a_stale_fingerprint_is_the_named_problem():
    admission = given.with_a_stale_grammar_fingerprint(given.an_admission())

    [problem] = admission_problems(
        admission,
        given.a_nuisance_census(),
        cve_baseline.grammar_fingerprint(),
        given.a_backend_registry(),
    )

    assert "grammar fingerprint" in problem


def _problems(admission: NuisanceAdmission, census: NuisanceCensus) -> list[str]:
    return admission_problems(
        admission, census, cve_baseline.grammar_fingerprint(), given.a_backend_registry()
    )


def test_an_admitted_server_the_walk_does_not_reach_is_refused():
    census = given.a_nuisance_census_with_the_second_flaw_under_another_package()

    problems = _problems(given.admitting_another_package_outside_the_walk(), census)

    assert problems == [f"{given.OTHER_PACKAGE}: not reached by the walk"]


def test_an_admitted_acceptance_server_outside_the_walk_passes():
    census = walk_given.a_nuisance_census(given.a_census_with_an_acceptance_server())

    assert _problems(given.admitting_the_acceptance_server(), census) == []


def test_a_wrong_reaching_flaw_is_refused_naming_both_flaws():
    admission = given.with_the_second_flaw_reaching(given.an_admission())

    [problem] = _problems(admission, given.a_nuisance_census())

    assert given.SERVER_PACKAGE in problem
    assert given.FIRST_FLAW in problem
    assert given.SECOND_FLAW in problem


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
