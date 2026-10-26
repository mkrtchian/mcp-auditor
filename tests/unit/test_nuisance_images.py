from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_admission_given as given
from evals import cve_baseline, cve_targets, nuisance_images
from evals.cve_grammar import MechanismClass
from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.holdout_kit import kit_launch
from evals.nuisance_admission import (
    AdmissionSettlement,
    AdmittedServer,
    BenignCall,
    NuisanceAdmission,
    admission_problems,
)

SERVICE = given.a_server([]).service


def test_the_three_image_namespaces_are_pairwise_distinct():
    tags = {
        cve_targets.image_tag("filesystem"),
        kit_launch.image_tag("filesystem"),
        nuisance_images.image_tag("filesystem"),
    }
    assert len(tags) == 3


@pytest.mark.parametrize("service", ["filesystem-patched", "sentinel"])
def test_an_acceptance_service_is_a_namespace_problem(service: str):
    [problem] = nuisance_images.namespace_problems(_with_service(service))
    assert service in problem


def test_a_clean_admission_has_no_namespace_problem():
    assert nuisance_images.namespace_problems(given.an_admission()) == []


def test_admission_problems_carries_the_namespace_problem():
    admission = _with_service("sentinel")

    problems = admission_problems(admission, given.a_census(), cve_baseline.grammar_fingerprint())

    assert any("sentinel" in problem for problem in problems)


def test_the_fingerprint_is_stable_over_the_same_server(tmp_path: Path):
    _write_dockerfile(tmp_path)
    server = given.an_admission().servers[0]

    first = nuisance_images.nuisance_fixture_fingerprint(server, tmp_path)
    second = nuisance_images.nuisance_fixture_fingerprint(server, tmp_path)

    assert first == second


def test_the_fingerprint_moves_when_a_counted_tools_class_changes(tmp_path: Path):
    _write_dockerfile(tmp_path)
    reader = _one_flaw_server(MechanismClass.READ_OUTSIDE_SCOPE)
    runner = _one_flaw_server(MechanismClass.COMMAND_EXECUTION)

    assert _fingerprint(reader, tmp_path) != _fingerprint(runner, tmp_path)


def test_the_fingerprint_moves_when_a_benign_calls_arguments_change(tmp_path: Path):
    _write_dockerfile(tmp_path)
    server = given.an_admission().servers[0]
    other = _with_benign_arguments(server, {"path": "/etc/passwd"})

    assert _fingerprint(server, tmp_path) != _fingerprint(other, tmp_path)


def test_the_fingerprint_moves_when_the_dockerfile_instructions_change(tmp_path: Path):
    _write_dockerfile(tmp_path)
    server = given.an_admission().servers[0]
    before = _fingerprint(server, tmp_path)

    _write_dockerfile(tmp_path, "FROM node:22\nRUN npm install demo@1.0.1\n")

    assert _fingerprint(server, tmp_path) != before


def test_the_fingerprint_moves_when_the_launch_changes(tmp_path: Path):
    _write_dockerfile(tmp_path)
    server = given.an_admission().servers[0]
    other = server.model_copy(update={"launch": ["node", "other.js"]})

    assert _fingerprint(server, tmp_path) != _fingerprint(other, tmp_path)


@pytest.mark.parametrize(
    "host",
    [
        PlantingHost(SymbolicUser.HOST, "/", has_network=False),
        PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv", has_network=False),
        PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True),
    ],
)
def test_the_fingerprint_moves_when_a_host_field_changes(tmp_path: Path, host: PlantingHost):
    _write_dockerfile(tmp_path)
    server = given.an_admission().servers[0]

    assert _fingerprint(server, tmp_path) != _fingerprint(given.with_host(server, host), tmp_path)


def test_the_fingerprint_is_unchanged_by_a_dockerfile_comment(tmp_path: Path):
    _write_dockerfile(tmp_path, "FROM node:22\nRUN npm install demo\n")
    server = given.an_admission().servers[0]
    before = _fingerprint(server, tmp_path)

    _write_dockerfile(tmp_path, "# pinned\nFROM node:22\n\n  # the server\nRUN npm install demo\n")

    assert _fingerprint(server, tmp_path) == before


def test_the_fingerprint_is_unchanged_by_an_exploit_or_a_settlement_change(tmp_path: Path):
    _write_dockerfile(tmp_path)
    server = given.an_admission().servers[0]
    before = _fingerprint(server, tmp_path)

    first, *rest = server.flaws
    moved_exploit = first.model_copy(
        update={"fix_check": first.fix_check.model_copy(update={"exploit_calls": ["other_tool"]})}
    )
    settled = AdmissionSettlement(
        server_package=server.server_package,
        flaw=None,
        field="runs_under_docker",
        value="true",
        reason="a different reason",
    )
    changed = server.model_copy(update={"flaws": [moved_exploit, *rest], "settlements": [settled]})

    assert _fingerprint(changed, tmp_path) == before


def _one_flaw_server(effect_class: MechanismClass) -> AdmittedServer:
    flaw = given.a_flaw_record(given.FIRST_FLAW, effect_class, given.PATCHED_VERSION)
    return given.a_server([flaw])


def _with_service(service: str) -> NuisanceAdmission:
    admission = given.an_admission()
    server = admission.servers[0].model_copy(update={"service": service})
    return admission.model_copy(update={"servers": [server]})


def _with_benign_arguments(server: AdmittedServer, arguments: dict[str, object]) -> AdmittedServer:
    first, *rest = server.flaws
    call = first.benign_calls[0]
    moved = first.model_copy(
        update={"benign_calls": [BenignCall(tool=call.tool, arguments=arguments)]}
    )
    return server.model_copy(update={"flaws": [moved, *rest]})


def _write_dockerfile(tmp_path: Path, text: str = "FROM node:22\nRUN npm install demo\n") -> None:
    (tmp_path / f"Dockerfile.{SERVICE}").write_text(text)


def _fingerprint(server: AdmittedServer, docker_directory: Path) -> str:
    return nuisance_images.nuisance_fixture_fingerprint(server, docker_directory)
