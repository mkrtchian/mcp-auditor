from pathlib import Path

import pytest

import tests.unit.nuisance.support.test_nuisance_fingerprint_given as given
import tests.unit.support.admission_mutations as mutations
import tests.unit.support.nuisance_admissions as admissions
from evals.cve import planting_base
from evals.cve.grammar import FlawClass
from evals.cve.nuisance.admission.admission import BackendFixture, ToolCall
from evals.cve.nuisance.fingerprint import (
    NuisanceFixtureSources,
    SuiteConfinement,
    fingerprinted_files,
    nuisance_fixture_fingerprint,
)
from evals.cve.planting_base import PlantingHost, SymbolicUser
from tests.unit.support.fictional_stand_ins import HOST, a_stand_ins_directory

FAKE_BACKEND = BackendFixture(provisioner="fake", images=["fake/backend:1.0"], network="fake-net")


def test_the_fingerprint_is_stable_over_the_same_server(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    sources = NuisanceFixtureSources(tmp_path)
    server = admissions.an_admission().servers[0]

    first = nuisance_fixture_fingerprint(server, sources)
    second = nuisance_fixture_fingerprint(server, sources)

    assert first == second


def test_the_fingerprint_moves_when_a_counted_tools_class_changes(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    sources = NuisanceFixtureSources(tmp_path)
    reader = given.one_flaw_server(FlawClass.READ_OUTSIDE_SCOPE)
    runner = given.one_flaw_server(FlawClass.COMMAND_EXECUTION)

    assert nuisance_fixture_fingerprint(reader, sources) != nuisance_fixture_fingerprint(
        runner, sources
    )


def test_the_fingerprint_moves_when_a_benign_calls_arguments_change(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    sources = NuisanceFixtureSources(tmp_path)
    server = admissions.an_admission().servers[0]
    other = mutations.with_the_first_benign_call(server, arguments={"path": "/etc/passwd"})

    assert nuisance_fixture_fingerprint(server, sources) != nuisance_fixture_fingerprint(
        other, sources
    )


def test_the_fingerprint_moves_when_a_benign_calls_expected_text_changes(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    sources = NuisanceFixtureSources(tmp_path)
    server = admissions.an_admission().servers[0]
    other = mutations.with_the_first_benign_call(server, expect="another answer")

    assert nuisance_fixture_fingerprint(server, sources) != nuisance_fixture_fingerprint(
        other, sources
    )


def test_the_fingerprint_moves_when_a_benign_calls_prerequisite_calls_change(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    sources = NuisanceFixtureSources(tmp_path)
    server = admissions.an_admission().servers[0]
    connected = mutations.with_the_first_benign_call(
        server, before=[ToolCall(tool="connect", arguments={"database": "app"})]
    )
    unrecorded = mutations.with_the_first_benign_call(server, before=None)

    assert nuisance_fixture_fingerprint(server, sources) != nuisance_fixture_fingerprint(
        connected, sources
    )
    assert nuisance_fixture_fingerprint(server, sources) != nuisance_fixture_fingerprint(
        unrecorded, sources
    )


def test_the_fingerprint_is_unchanged_by_the_provenance_records(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    sources = NuisanceFixtureSources(tmp_path)
    server = admissions.an_admission().servers[0]

    assert nuisance_fixture_fingerprint(server, sources) == nuisance_fixture_fingerprint(
        given.with_provenance_records(server), sources
    )


def test_the_fingerprint_moves_when_the_dockerfile_instructions_change(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    sources = NuisanceFixtureSources(tmp_path)
    server = admissions.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, sources)

    given.written_dockerfile(tmp_path, "FROM node:22\nRUN npm install demo@1.0.1\n")

    assert nuisance_fixture_fingerprint(server, sources) != before


def test_the_fingerprint_moves_when_a_backend_fixture_is_set(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    sources = NuisanceFixtureSources(tmp_path, admissions.a_backend_registry())
    server = admissions.an_admission().servers[0]

    assert nuisance_fixture_fingerprint(server, sources) != nuisance_fixture_fingerprint(
        mutations.with_a_backend(server, FAKE_BACKEND), sources
    )


def test_the_fingerprint_moves_when_a_backend_image_changes(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    sources = NuisanceFixtureSources(tmp_path, admissions.a_backend_registry())
    server = admissions.an_admission().servers[0]
    one = mutations.with_a_backend(server, FAKE_BACKEND)
    two = mutations.with_a_backend(
        server, FAKE_BACKEND.model_copy(update={"images": ["fake/backend:2.0"]})
    )

    assert nuisance_fixture_fingerprint(one, sources) != nuisance_fixture_fingerprint(two, sources)


def test_the_fingerprint_moves_when_the_launch_changes(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    sources = NuisanceFixtureSources(tmp_path)
    server = admissions.an_admission().servers[0]
    other = server.model_copy(update={"launch": ["node", "other.js"]})

    assert nuisance_fixture_fingerprint(server, sources) != nuisance_fixture_fingerprint(
        other, sources
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
    sources = NuisanceFixtureSources(tmp_path)
    server = admissions.an_admission().servers[0]

    assert nuisance_fixture_fingerprint(server, sources) != nuisance_fixture_fingerprint(
        mutations.with_host(server, host), sources
    )


def test_the_fingerprint_is_unchanged_by_a_dockerfile_comment(tmp_path: Path):
    given.written_dockerfile(tmp_path, "FROM node:22\nRUN npm install demo\n")
    sources = NuisanceFixtureSources(tmp_path)
    server = admissions.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, sources)

    given.written_dockerfile(
        tmp_path, "# pinned\nFROM node:22\n\n  # the server\nRUN npm install demo\n"
    )

    assert nuisance_fixture_fingerprint(server, sources) == before


def test_the_fingerprint_is_unchanged_by_an_exploit_or_a_settlement_change(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    sources = NuisanceFixtureSources(tmp_path)
    server = admissions.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, sources)

    changed = given.with_a_moved_exploit_and_a_settlement(server)

    assert nuisance_fixture_fingerprint(changed, sources) == before


@pytest.mark.parametrize(
    ("name", "after"), [(name, after) for name, _, after in given.SERVED_CHANGES]
)
def test_the_fingerprint_moves_when_a_served_file_of_the_backend_changes(
    tmp_path: Path, name: str, after: str
):
    given.written_dockerfile(tmp_path)
    sources = NuisanceFixtureSources(tmp_path, given.a_registry_serving(tmp_path))
    server = mutations.with_a_backend(admissions.an_admission().servers[0], FAKE_BACKEND)
    first = nuisance_fixture_fingerprint(server, sources)

    (tmp_path / name).write_text(after)

    assert nuisance_fixture_fingerprint(server, sources) != first


def test_the_fingerprint_is_unchanged_by_served_files_for_a_server_with_no_backend(
    tmp_path: Path,
):
    given.written_dockerfile(tmp_path)
    sources = NuisanceFixtureSources(tmp_path, given.a_registry_serving(tmp_path))
    server = admissions.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, sources)

    for name, _, after in given.SERVED_CHANGES:
        (tmp_path / name).write_text(after)

    assert nuisance_fixture_fingerprint(server, sources) == before


def test_the_fingerprint_moves_when_the_stand_in_image_of_a_public_name_changes(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    given.written_public_name_dockerfiles(tmp_path)
    sources = NuisanceFixtureSources(tmp_path, stand_ins_directory=a_stand_ins_directory(tmp_path))
    server = given.serving_a_public_name(admissions.an_admission().servers[0])
    before = nuisance_fixture_fingerprint(server, sources)

    given.written_public_name_dockerfiles(tmp_path, stand_in="FROM python:3.13\nRUN true\n")

    assert nuisance_fixture_fingerprint(server, sources) != before


def test_the_fingerprinted_files_name_the_stand_ins_of_the_sources_directory(tmp_path: Path):
    stand_ins = a_stand_ins_directory(tmp_path)
    sources = NuisanceFixtureSources(tmp_path, stand_ins_directory=stand_ins)
    server = given.serving_a_public_name(admissions.an_admission().servers[0])

    assert stand_ins / f"{HOST}.json" in fingerprinted_files(server, sources)


def test_the_fingerprint_is_unchanged_by_the_stand_in_image_for_a_server_with_no_public_name(
    tmp_path: Path,
):
    given.written_dockerfile(tmp_path)
    given.written_public_name_dockerfiles(tmp_path)
    sources = NuisanceFixtureSources(tmp_path)
    server = admissions.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, sources)

    given.written_public_name_dockerfiles(tmp_path, stand_in="FROM python:3.13\nRUN true\n")

    assert nuisance_fixture_fingerprint(server, sources) == before


def test_the_fingerprint_moves_when_the_confinement_code_changes(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    confinement = given.a_confinement_copy(tmp_path)
    sources = NuisanceFixtureSources(tmp_path, confinement=SuiteConfinement(source=confinement))
    server = admissions.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, sources)

    confinement.write_text(
        confinement.read_text().replace(
            'LAUNCH_LABEL = f"{LABEL}-launch"', 'LAUNCH_LABEL = f"{LABEL}-start"'
        )
    )

    assert nuisance_fixture_fingerprint(server, sources) != before


def test_the_fingerprint_is_unchanged_by_a_comment_in_the_confinement(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    confinement = given.a_confinement_copy(tmp_path)
    sources = NuisanceFixtureSources(tmp_path, confinement=SuiteConfinement(source=confinement))
    server = admissions.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, sources)

    confinement.write_text(confinement.read_text() + "\n# a note on the bound\n")

    assert nuisance_fixture_fingerprint(server, sources) == before


def test_the_fingerprint_moves_when_the_confinement_options_change(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    server = admissions.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, NuisanceFixtureSources(tmp_path))
    options = [*planting_base.confinement_args(), "--pids-limit", "512"]

    moved = NuisanceFixtureSources(tmp_path, confinement=SuiteConfinement(options=lambda: options))

    assert nuisance_fixture_fingerprint(server, moved) != before


def test_the_fingerprint_moves_when_the_resolver_option_changes(tmp_path: Path):
    given.written_dockerfile(tmp_path)
    server = admissions.an_admission().servers[0]
    before = nuisance_fixture_fingerprint(server, NuisanceFixtureSources(tmp_path))
    resolver = SuiteConfinement(resolver=lambda: ["--dns-search", "fict"])

    moved = NuisanceFixtureSources(tmp_path, confinement=resolver)

    assert nuisance_fixture_fingerprint(server, moved) != before
