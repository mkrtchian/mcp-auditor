from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_admission_edits_given as edits
import tests.unit.support.test_nuisance_admission_given as admission_given
import tests.unit.support.test_nuisance_fingerprint_given as given
from evals import cve_planting_base, nuisance_confinement
from evals.cve_grammar import MechanismClass
from evals.cve_planting_base import PlantingHost, SymbolicUser
from evals.fixture_provenance import StandInRecord
from evals.nuisance_admission import AdmissionSettlement, BackendFixture, ToolCall
from evals.nuisance_admission_records import SeedRecord
from evals.nuisance_backends import BACKENDS
from evals.nuisance_fingerprint import nuisance_fixture_fingerprint

FAKE_BACKEND = BackendFixture(provisioner="fake", image="fake/backend:1.0", network="fake-net")


def test_the_fingerprint_is_stable_over_the_same_server(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    server = admission_given.an_admission().servers[0]

    first = nuisance_fixture_fingerprint(server, tmp_path)
    second = nuisance_fixture_fingerprint(server, tmp_path)

    assert first == second


def test_the_fingerprint_moves_when_a_counted_tools_class_changes(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    reader = given.one_flaw_server(MechanismClass.READ_OUTSIDE_SCOPE)
    runner = given.one_flaw_server(MechanismClass.COMMAND_EXECUTION)

    assert nuisance_fixture_fingerprint(reader, tmp_path) != nuisance_fixture_fingerprint(
        runner, tmp_path
    )


def test_the_fingerprint_moves_when_a_benign_calls_arguments_change(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    server = admission_given.an_admission().servers[0]
    other = edits.with_the_first_benign_call(server, arguments={"path": "/etc/passwd"})

    assert nuisance_fixture_fingerprint(server, tmp_path) != nuisance_fixture_fingerprint(
        other, tmp_path
    )


def test_the_fingerprint_moves_when_a_benign_calls_expected_text_changes(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    server = admission_given.an_admission().servers[0]
    other = edits.with_the_first_benign_call(server, expect="another answer")

    assert nuisance_fixture_fingerprint(server, tmp_path) != nuisance_fixture_fingerprint(
        other, tmp_path
    )


def test_the_fingerprint_moves_when_a_benign_calls_prerequisite_calls_change(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    server = admission_given.an_admission().servers[0]
    connected = edits.with_the_first_benign_call(
        server, before=[ToolCall(tool="connect", arguments={"database": "app"})]
    )
    unrecorded = edits.with_the_first_benign_call(server, before=None)

    assert nuisance_fixture_fingerprint(server, tmp_path) != nuisance_fixture_fingerprint(
        connected, tmp_path
    )
    assert nuisance_fixture_fingerprint(server, tmp_path) != nuisance_fixture_fingerprint(
        unrecorded, tmp_path
    )


def test_the_fingerprint_is_unchanged_by_the_provenance_records(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    server = admission_given.an_admission().servers[0]
    seed = SeedRecord(item="/agents.yaml", kind="written")
    stand_in = StandInRecord(
        replaces="api.example.com",
        reason="no network",
        file="evals/docker/Dockerfile.x",
        capture="evals/stand_ins/api.example.com.json",
        outputs=[],
    )
    recorded = server.model_copy(update={"seeds": [seed], "stand_ins": [stand_in]})

    assert nuisance_fixture_fingerprint(server, tmp_path) == nuisance_fixture_fingerprint(
        recorded, tmp_path
    )


def test_the_fingerprint_moves_when_the_dockerfile_instructions_change(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    server = admission_given.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, tmp_path)

    given.written_dockerfile(tmp_path, "FROM node:22\nRUN npm install demo@1.0.1\n")

    assert nuisance_fixture_fingerprint(server, tmp_path) != before


def test_the_fingerprint_moves_when_a_backend_fixture_is_set(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    server = admission_given.an_admission().servers[0]
    backend = BackendFixture(provisioner="doris", image="fake/backend:1.0", network="net")

    assert nuisance_fixture_fingerprint(server, tmp_path) != nuisance_fixture_fingerprint(
        admission_given.with_a_backend(server, backend), tmp_path
    )


def test_the_fingerprint_moves_when_a_backend_image_changes(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    server = admission_given.an_admission().servers[0]
    one = admission_given.with_a_backend(
        server, BackendFixture(provisioner="doris", image="fake/backend:1.0", network="net")
    )
    two = admission_given.with_a_backend(
        server, BackendFixture(provisioner="doris", image="fake/backend:2.0", network="net")
    )

    assert nuisance_fixture_fingerprint(one, tmp_path) != nuisance_fixture_fingerprint(
        two, tmp_path
    )


def test_the_fingerprint_moves_when_the_launch_changes(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    server = admission_given.an_admission().servers[0]
    other = server.model_copy(update={"launch": ["node", "other.js"]})

    assert nuisance_fixture_fingerprint(server, tmp_path) != nuisance_fixture_fingerprint(
        other, tmp_path
    )


@pytest.mark.parametrize(
    "host",
    [
        PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv", has_network=False),
        PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True),
    ],
)
def test_the_fingerprint_moves_when_a_host_field_changes(tmp_path: Path, host: PlantingHost):
    given.written_dockerfile(tmp_path)
    server = admission_given.an_admission().servers[0]

    assert nuisance_fixture_fingerprint(server, tmp_path) != nuisance_fixture_fingerprint(
        admission_given.with_host(server, host), tmp_path
    )


def test_the_fingerprint_is_unchanged_by_a_dockerfile_comment(tmp_path: Path):
    given.written_dockerfile(tmp_path, "FROM node:22\nRUN npm install demo\n")
    server = admission_given.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, tmp_path)

    given.written_dockerfile(
        tmp_path, "# pinned\nFROM node:22\n\n  # the server\nRUN npm install demo\n"
    )

    assert nuisance_fixture_fingerprint(server, tmp_path) == before


def test_the_fingerprint_is_unchanged_by_an_exploit_or_a_settlement_change(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    server = admission_given.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, tmp_path)

    moved_exploit = edits.with_the_first_flaw(
        server,
        lambda flaw: flaw.model_copy(
            update={
                "fix_check": flaw.fix_check.model_copy(update={"exploit_calls": ["other_tool"]})
            }
        ),
    )
    settled = AdmissionSettlement(
        server_package=server.server_package,
        flaw=None,
        field="runs_under_docker",
        value="true",
        reason="a different reason",
    )
    changed = moved_exploit.model_copy(update={"settlements": [settled]})

    assert nuisance_fixture_fingerprint(changed, tmp_path) == before


@pytest.mark.parametrize(
    ("name", "after"), [(name, after) for name, _, after in given.SERVED_CHANGES]
)
def test_the_fingerprint_moves_when_a_served_file_of_the_backend_changes(
    tmp_path: Path, name: str, after: str
):
    given.written_dockerfile(tmp_path)
    backends = given.a_registry_serving(tmp_path)
    server = admission_given.with_a_backend(admission_given.an_admission().servers[0], FAKE_BACKEND)
    first = nuisance_fixture_fingerprint(server, tmp_path, backends)

    (tmp_path / name).write_text(after)

    assert nuisance_fixture_fingerprint(server, tmp_path, backends) != first


def test_the_fingerprint_is_unchanged_by_served_files_for_a_server_with_no_backend(
    tmp_path: Path,
):
    given.written_dockerfile(tmp_path)
    backends = given.a_registry_serving(tmp_path)
    server = admission_given.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, tmp_path, backends)

    for name, _, after in given.SERVED_CHANGES:
        (tmp_path / name).write_text(after)

    assert nuisance_fixture_fingerprint(server, tmp_path, backends) == before


def test_the_fingerprint_moves_when_the_stand_in_image_of_a_public_name_changes(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    given.written_public_name_dockerfiles(tmp_path)
    server = given.serving_a_public_name(admission_given.an_admission().servers[0])
    before = nuisance_fixture_fingerprint(server, tmp_path)

    given.written_public_name_dockerfiles(tmp_path, stand_in="FROM python:3.13\nRUN true\n")

    assert nuisance_fixture_fingerprint(server, tmp_path) != before


def test_the_fingerprint_is_unchanged_by_the_stand_in_image_for_a_server_with_no_public_name(
    tmp_path: Path,
):
    given.written_dockerfile(tmp_path)
    given.written_public_name_dockerfiles(tmp_path)
    server = admission_given.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, tmp_path)

    given.written_public_name_dockerfiles(tmp_path, stand_in="FROM python:3.13\nRUN true\n")

    assert nuisance_fixture_fingerprint(server, tmp_path) == before


def test_the_fingerprint_moves_when_the_confinement_code_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    given.written_dockerfile(tmp_path)
    confinement = given.a_confinement_copy(tmp_path, monkeypatch)
    server = admission_given.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, tmp_path)

    confinement.write_text(
        confinement.read_text().replace('MEMORY_BOUND = "4g"', 'MEMORY_BOUND = "8g"')
    )

    assert nuisance_fixture_fingerprint(server, tmp_path) != before


def test_the_fingerprint_is_unchanged_by_a_comment_in_the_confinement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    given.written_dockerfile(tmp_path)
    confinement = given.a_confinement_copy(tmp_path, monkeypatch)
    server = admission_given.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, tmp_path)

    confinement.write_text(confinement.read_text() + "\n# a note on the bound\n")

    assert nuisance_fixture_fingerprint(server, tmp_path) == before


def test_the_fingerprint_moves_when_the_confinement_options_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    given.written_dockerfile(tmp_path)
    server = admission_given.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, tmp_path)
    options = [*nuisance_confinement.nuisance_confinement_args(), "--pids-limit", "512"]

    monkeypatch.setattr(nuisance_confinement, "nuisance_confinement_args", lambda: options)

    assert nuisance_fixture_fingerprint(server, tmp_path) != before


def test_the_fingerprint_moves_when_the_resolver_option_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    given.written_dockerfile(tmp_path)
    server = admission_given.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, tmp_path)

    monkeypatch.setattr(cve_planting_base, "resolver_args", lambda: ["--dns-search", "fict"])

    assert nuisance_fixture_fingerprint(server, tmp_path) != before


@pytest.mark.parametrize("key", sorted(BACKENDS))
def test_every_served_path_of_a_registered_backend_exists(key: str):
    missing = [path for path in BACKENDS[key].served if not path.is_file()]

    assert missing == []
