import pytest

import tests.unit.support.test_nuisance_fixture_sources_given as given
import tests.unit.support.test_nuisance_fixture_sources_then as then
from evals.cve_images import dockerfile_instructions
from evals.docker_paths import image_dockerfile
from evals.nuisance_admission import AdmittedServer

_SHA256 = "a" * 64
_COMMIT = "0123456789abcdef0123456789abcdef01234567"
_ARCHIVE = "https://example.com/release.tar.gz"
_REPOSITORY = "https://github.com/example/project.git#v1.0.0"

ADMITTED = given.admitted_servers()


@pytest.mark.parametrize("server", ADMITTED, ids=lambda server: server.service)
def test_the_run_dockerfile_copies_in_nothing_the_fingerprint_misses(server: AdmittedServer):
    then.copies_nothing_unsourced(dockerfile_instructions(image_dockerfile(server.service)))


@pytest.mark.parametrize("server", ADMITTED, ids=lambda server: server.service)
def test_each_backend_dockerfile_copies_in_nothing_the_fingerprint_misses(server: AdmittedServer):
    dockerfiles = [
        path for path in then.backend_served(server) if path.name.startswith("Dockerfile.")
    ]

    for dockerfile in dockerfiles:
        then.copies_nothing_unsourced(dockerfile_instructions(dockerfile))


@pytest.mark.parametrize("server", ADMITTED, ids=lambda server: server.service)
def test_every_seed_pin_is_in_the_fingerprinted_content(server: AdmittedServer):
    then.every_seed_pin_is_fingerprinted(server)


@pytest.mark.parametrize("server", ADMITTED, ids=lambda server: server.service)
def test_every_stand_in_is_a_fingerprinted_file_holding_its_requests(server: AdmittedServer):
    then.every_stand_in_is_a_fingerprinted_file(server)


@pytest.mark.parametrize(
    "instructions",
    [
        ["COPY --from=build /app /app"],
        [f"ADD --checksum=sha256:{_SHA256} {_ARCHIVE} /opt/"],
        [f"ADD --checksum={_COMMIT} {_REPOSITORY} /src"],
        ["ADD \\", f"--checksum=sha256:{_SHA256} \\", f"{_ARCHIVE} /opt/"],
    ],
    ids=["copy from a stage", "http with sha256", "git with a commit", "continued lines"],
)
def test_a_copy_from_a_stage_or_a_checksummed_remote_add_passes(instructions: list[str]):
    then.copies_nothing_unsourced(instructions)


@pytest.mark.parametrize(
    "instructions",
    [
        ["COPY seed.txt /tmp/"],
        ["ADD seed.tar /tmp/"],
        [f"ADD {_ARCHIVE} /opt/"],
        [f"ADD --checksum=sha256:{_SHA256[:40]} {_ARCHIVE} /opt/"],
        [f"ADD --checksum=sha512:{'a' * 128} {_ARCHIVE} /opt/"],
        [f"ADD {_REPOSITORY} /src"],
        [f"ADD --checksum={_COMMIT[:12]} {_REPOSITORY} /src"],
        [f"ADD --checksum=sha256:{_SHA256} {_REPOSITORY} /src"],
        [f"ADD --checksum={_COMMIT} {_ARCHIVE} /opt/"],
    ],
    ids=[
        "local copy",
        "local add",
        "http without checksum",
        "http with a short digest",
        "http with another algorithm",
        "git without checksum",
        "git with an abbreviated commit",
        "git with a sha256 checksum",
        "http with a commit checksum",
    ],
)
def test_a_local_copy_or_an_unpinned_remote_add_is_refused(instructions: list[str]):
    then.refuses_the_copy(instructions)


def test_a_seed_pin_absent_from_the_fingerprinted_content_is_refused():
    server = given.a_server_seeding_with_the_pin(ADMITTED[0], _COMMIT)

    with pytest.raises(AssertionError):
        then.every_seed_pin_is_fingerprinted(server)


def test_a_stand_in_file_the_fingerprint_does_not_cover_is_refused():
    server = given.a_server_with_a_stand_in(ADMITTED[0], "evals/cve_layout.py", "def ")

    with pytest.raises(AssertionError):
        then.every_stand_in_is_a_fingerprinted_file(server)


def test_a_stand_in_request_its_file_does_not_hold_is_refused():
    dockerfile = image_dockerfile(ADMITTED[0].service).relative_to(then.REPO_ROOT)
    server = given.a_server_with_a_stand_in(ADMITTED[0], str(dockerfile), "GET /never/served")

    with pytest.raises(AssertionError):
        then.every_stand_in_is_a_fingerprinted_file(server)


def test_a_stand_in_in_the_run_dockerfile_holding_its_request_passes():
    dockerfile = image_dockerfile(ADMITTED[0].service).relative_to(then.REPO_ROOT)
    server = given.a_server_with_a_stand_in(ADMITTED[0], str(dockerfile), "FROM ")

    then.every_stand_in_is_a_fingerprinted_file(server)
