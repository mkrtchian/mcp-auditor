from dataclasses import replace
from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_admission_given as given
from evals.cve_grammar import MechanismClass
from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.fixture_provenance import StandInRecord
from evals.nuisance_admission import AdmissionSettlement, AdmittedServer, ToolCall
from evals.nuisance_admission_records import SeedRecord
from evals.nuisance_backends import BACKENDS, RegisteredBackend
from evals.nuisance_fingerprint import nuisance_fixture_fingerprint

SERVICE = given.a_server([]).service
FAKE_BACKEND = given.BackendFixture(
    provisioner="fake", image="fake/backend:1.0", network="fake-net"
)
SERVED_CHANGES = [
    ("Dockerfile.fake-responder", "FROM python:3.13\n", "FROM python:3.14\n"),
    ("fake_backend.py", "ANSWER = 1\n", "ANSWER = 2\n"),
    ("capture.json", '{"body": "one"}', '{"body": "two"}'),
]


def test_the_fingerprint_is_stable_over_the_same_server(tmp_path: Path):
    _write_dockerfile(tmp_path)
    server = given.an_admission().servers[0]

    first = nuisance_fixture_fingerprint(server, tmp_path)
    second = nuisance_fixture_fingerprint(server, tmp_path)

    assert first == second


def test_the_fingerprint_moves_when_a_counted_tools_class_changes(tmp_path: Path):
    _write_dockerfile(tmp_path)
    reader = _one_flaw_server(MechanismClass.READ_OUTSIDE_SCOPE)
    runner = _one_flaw_server(MechanismClass.COMMAND_EXECUTION)

    assert _fingerprint(reader, tmp_path) != _fingerprint(runner, tmp_path)


def test_the_fingerprint_moves_when_a_benign_calls_arguments_change(tmp_path: Path):
    _write_dockerfile(tmp_path)
    server = given.an_admission().servers[0]
    other = _with_first_benign_call(server, arguments={"path": "/etc/passwd"})

    assert _fingerprint(server, tmp_path) != _fingerprint(other, tmp_path)


def test_the_fingerprint_moves_when_a_benign_calls_expected_text_changes(tmp_path: Path):
    _write_dockerfile(tmp_path)
    server = given.an_admission().servers[0]
    other = _with_first_benign_call(server, expect="another answer")

    assert _fingerprint(server, tmp_path) != _fingerprint(other, tmp_path)


def test_the_fingerprint_moves_when_a_benign_calls_prerequisite_calls_change(tmp_path: Path):
    _write_dockerfile(tmp_path)
    server = given.an_admission().servers[0]
    connected = _with_first_benign_call(
        server, before=[ToolCall(tool="connect", arguments={"database": "app"})]
    )
    unrecorded = _with_first_benign_call(server, before=None)

    assert _fingerprint(server, tmp_path) != _fingerprint(connected, tmp_path)
    assert _fingerprint(server, tmp_path) != _fingerprint(unrecorded, tmp_path)


def test_the_fingerprint_is_unchanged_by_the_provenance_records(tmp_path: Path):
    _write_dockerfile(tmp_path)
    server = given.an_admission().servers[0]
    seed = SeedRecord(item="/agents.yaml", kind="written")
    stand_in = StandInRecord(
        replaces="api.example.com",
        reason="no network",
        file="evals/docker/Dockerfile.x",
        capture="evals/stand_ins/api.example.com.json",
        outputs=[],
    )
    recorded = server.model_copy(update={"seeds": [seed], "stand_ins": [stand_in]})

    assert _fingerprint(server, tmp_path) == _fingerprint(recorded, tmp_path)


def test_the_fingerprint_moves_when_the_dockerfile_instructions_change(tmp_path: Path):
    _write_dockerfile(tmp_path)
    server = given.an_admission().servers[0]
    before = _fingerprint(server, tmp_path)

    _write_dockerfile(tmp_path, "FROM node:22\nRUN npm install demo@1.0.1\n")

    assert _fingerprint(server, tmp_path) != before


def test_the_fingerprint_moves_when_a_backend_fixture_is_set(tmp_path: Path):
    _write_dockerfile(tmp_path)
    server = given.an_admission().servers[0]
    backend = given.BackendFixture(provisioner="doris", image="fake/backend:1.0", network="net")

    assert _fingerprint(server, tmp_path) != _fingerprint(
        given.with_a_backend(server, backend), tmp_path
    )


def test_the_fingerprint_moves_when_a_backend_image_changes(tmp_path: Path):
    _write_dockerfile(tmp_path)
    server = given.an_admission().servers[0]
    one = given.with_a_backend(
        server, given.BackendFixture(provisioner="doris", image="fake/backend:1.0", network="net")
    )
    two = given.with_a_backend(
        server, given.BackendFixture(provisioner="doris", image="fake/backend:2.0", network="net")
    )

    assert _fingerprint(one, tmp_path) != _fingerprint(two, tmp_path)


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


@pytest.mark.parametrize(("name", "after"), [(name, after) for name, _, after in SERVED_CHANGES])
def test_the_fingerprint_moves_when_a_served_file_of_the_backend_changes(
    tmp_path: Path, name: str, after: str
):
    _write_dockerfile(tmp_path)
    backends = _a_registry_serving(tmp_path)
    server = given.with_a_backend(given.an_admission().servers[0], FAKE_BACKEND)
    first = nuisance_fixture_fingerprint(server, tmp_path, backends)

    (tmp_path / name).write_text(after)

    assert nuisance_fixture_fingerprint(server, tmp_path, backends) != first


def test_the_fingerprint_is_unchanged_by_served_files_for_a_server_with_no_backend(
    tmp_path: Path,
):
    _write_dockerfile(tmp_path)
    backends = _a_registry_serving(tmp_path)
    server = given.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, tmp_path, backends)

    for name, _, after in SERVED_CHANGES:
        (tmp_path / name).write_text(after)

    assert nuisance_fixture_fingerprint(server, tmp_path, backends) == before


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_every_served_path_of_a_registered_backend_exists(key: str):
    missing = [path for path in BACKENDS[key].served if not path.is_file()]

    assert missing == []


def _a_registry_serving(directory: Path) -> dict[str, RegisteredBackend]:
    for name, before, _ in SERVED_CHANGES:
        (directory / name).write_text(before)
    served = tuple(directory / name for name, _, _ in SERVED_CHANGES)
    return {"fake": replace(given.a_backend_registry()["fake"], served=served)}


def _one_flaw_server(effect_class: MechanismClass) -> AdmittedServer:
    flaw = given.a_flaw_record(given.FIRST_FLAW, effect_class, given.PATCHED_VERSION)
    return given.a_server([flaw])


def _with_first_benign_call(server: AdmittedServer, **update: object) -> AdmittedServer:
    first, *rest = server.flaws
    moved = first.model_copy(
        update={"benign_calls": [first.benign_calls[0].model_copy(update=update)]}
    )
    return server.model_copy(update={"flaws": [moved, *rest]})


def _write_dockerfile(tmp_path: Path, text: str = "FROM node:22\nRUN npm install demo\n") -> None:
    (tmp_path / f"Dockerfile.{SERVICE}").write_text(text)


def _fingerprint(server: AdmittedServer, docker_directory: Path) -> str:
    return nuisance_fixture_fingerprint(server, docker_directory)
