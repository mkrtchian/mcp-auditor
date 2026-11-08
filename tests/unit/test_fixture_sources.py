from pathlib import Path

import pytest

from evals.fixture_provenance import StandInOutput, StandInRecord
from evals.fixture_sources import (
    unfingerprinted_pins,
    unfingerprinted_stand_in_files,
    unheld_requests,
    unreplayed_captures,
    unsourced_copies,
)
from evals.nuisance_admission_records import SeedRecord

_SHA256 = "a" * 64
_COMMIT = "0123456789abcdef0123456789abcdef01234567"
_ARCHIVE = "https://example.com/release.tar.gz"
_REPOSITORY = "https://github.com/example/project.git#v1.0.0"


@pytest.mark.parametrize(
    "instructions",
    [
        [f"FROM node:22@sha256:{_SHA256} AS build", "COPY --from=build /app /app"],
        [f"COPY --from=node:22@sha256:{_SHA256} /usr/local/bin/node /usr/local/bin/"],
        [f"ADD --checksum=sha256:{_SHA256} {_ARCHIVE} /opt/"],
        [f"ADD --checksum={_COMMIT} {_REPOSITORY} /src"],
        ["ADD \\", f"--checksum=sha256:{_SHA256} \\", f"{_ARCHIVE} /opt/"],
    ],
    ids=[
        "copy from a stage",
        "copy from an image pinned by digest",
        "http with sha256",
        "git with a commit",
        "continued lines",
    ],
)
def test_a_copy_from_a_stage_or_a_checksummed_remote_add_passes(instructions: list[str]):
    assert unsourced_copies(instructions) == []


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
        ["COPY --from=node:22 /usr/local/bin/node /usr/local/bin/"],
        ["COPY --from=build /app /app"],
        ["COPY --from=build /app /app", f"FROM node:22@sha256:{_SHA256} AS build"],
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
        "copy from an image without a digest",
        "copy from an undeclared stage",
        "copy from a stage declared later",
    ],
)
def test_a_local_copy_or_an_unpinned_remote_add_is_refused(instructions: list[str]):
    assert unsourced_copies(instructions) != []


def test_a_seed_pin_in_the_covered_text_passes():
    assert unfingerprinted_pins([_a_seed_pinned(_COMMIT)], f"RUN git checkout {_COMMIT}") == []


def test_a_seed_pin_absent_from_the_covered_text_is_refused():
    assert unfingerprinted_pins([_a_seed_pinned(_COMMIT)], "RUN true") == [_COMMIT]


def test_a_seed_without_a_pin_needs_no_covered_text():
    assert unfingerprinted_pins([_a_seed_pinned(None)], "") == []


def test_a_stand_in_in_a_covered_file_holding_its_request_passes(tmp_path: Path):
    (tmp_path / "Dockerfile.responder").write_text("FROM busybox\n# GET /api/v1/items\n")
    stand_in = _a_stand_in("Dockerfile.responder", "GET /api/v1/items")

    assert (
        unfingerprinted_stand_in_files(stand_in, [tmp_path / "Dockerfile.responder"], tmp_path)
        == []
    )
    assert unheld_requests(stand_in, tmp_path) == []


def test_a_stand_in_file_outside_the_covered_set_is_refused(tmp_path: Path):
    (tmp_path / "fixture.py").write_text("GET /api/v1/items")
    stand_in = _a_stand_in("fixture.py", "GET /api/v1/items")

    assert unfingerprinted_stand_in_files(stand_in, [tmp_path / "other.py"], tmp_path) == [
        "fixture.py"
    ]


def test_a_stand_in_capture_outside_the_covered_set_is_refused(tmp_path: Path):
    stand_in = _a_stand_in("responder.py", "GET /").model_copy(update={"capture": "host.json"})

    assert unfingerprinted_stand_in_files(stand_in, [tmp_path / "responder.py"], tmp_path) == [
        "host.json"
    ]


def test_a_stand_in_request_its_file_does_not_hold_is_refused(tmp_path: Path):
    (tmp_path / "responder.py").write_text("GET /api/v1/items")
    stand_in = _a_stand_in("responder.py", "GET /never/served")

    assert unheld_requests(stand_in, tmp_path) == ["GET /never/served"]


def test_a_capture_backed_stand_in_served_by_the_replayer_holds_its_requests(tmp_path: Path):
    (tmp_path / "Dockerfile.stand-in").write_text("FROM python\n")
    stand_in = _a_captured_stand_in("Dockerfile.stand-in", "the page a browser fetches")

    assert unheld_requests(stand_in, tmp_path) == []
    assert unreplayed_captures(stand_in, tmp_path / "Dockerfile.stand-in", tmp_path) == []


def test_a_capture_declared_on_another_file_than_the_replayer_is_refused(tmp_path: Path):
    stand_in = _a_captured_stand_in("responder.py", "GET /")

    assert unreplayed_captures(stand_in, tmp_path / "Dockerfile.stand-in", tmp_path) == [
        "responder.py"
    ]


def test_a_stand_in_without_a_capture_needs_no_replayer(tmp_path: Path):
    stand_in = _a_stand_in("responder.py", "GET /")

    assert unreplayed_captures(stand_in, tmp_path / "Dockerfile.stand-in", tmp_path) == []


def _a_captured_stand_in(file: str, request: str) -> StandInRecord:
    return _a_stand_in(file, request).model_copy(update={"capture": "host.json"})


def _a_seed_pinned(pin: str | None) -> SeedRecord:
    return SeedRecord(item="/seed.txt", kind="published_sample", citation="README", pin=pin)


def _a_stand_in(file: str, request: str) -> StandInRecord:
    output = StandInOutput(request=request, source="software_sources", citation="API reference")
    return StandInRecord(
        replaces="a fictional backend", reason="needs a device", file=file, outputs=[output]
    )
