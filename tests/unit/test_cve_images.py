from pathlib import Path

import pytest

import tests.unit.support.test_cve_images_given as given
from evals import nuisance_images
from evals.cve_images import (
    COMPOSE_BUILD_BATCH_SIZE,
    ComposeImageStore,
    ImageBuildFailed,
    compose_build,
    dockerfile_fingerprint,
    ensure_images,
    stale_services,
    unpinned_bases,
)
from evals.cve_targets import image_tag
from tests.fakes.image_store import FakeImageStore

FILESYSTEM_TAG = image_tag("filesystem")
SENTINEL_TAG = image_tag("sentinel")
DIGEST = "sha256:" + "0123456789abcdef" * 4


def test_a_tag_carrying_its_dockerfile_fingerprint_is_not_rebuilt():
    current = dockerfile_fingerprint("filesystem")
    store = FakeImageStore({FILESYSTEM_TAG: current})

    rebuilt = ensure_images(["filesystem"], store)

    assert rebuilt == []
    assert store.builds == []


@pytest.mark.parametrize(
    "labels",
    [{}, {FILESYSTEM_TAG: None}, {FILESYSTEM_TAG: dockerfile_fingerprint("fetch")}],
    ids=["absent", "unlabeled", "another-fingerprint"],
)
def test_a_stale_tag_is_rebuilt(labels: dict[str, str | None]):
    store = FakeImageStore(labels)

    rebuilt = ensure_images(["filesystem"], store)

    assert rebuilt == ["filesystem"]
    assert store.builds == [["filesystem"]]


def test_only_the_stale_services_are_rebuilt_in_input_order_once_each():
    store = FakeImageStore({FILESYSTEM_TAG: dockerfile_fingerprint("filesystem")})

    rebuilt = ensure_images(["sentinel", "filesystem", "fetch", "sentinel"], store)

    assert rebuilt == ["sentinel", "fetch"]
    assert store.builds == [["sentinel", "fetch"]]


def test_nothing_is_rebuilt_when_every_tag_is_current():
    store = FakeImageStore(
        {
            FILESYSTEM_TAG: dockerfile_fingerprint("filesystem"),
            SENTINEL_TAG: dockerfile_fingerprint("sentinel"),
        }
    )

    assert ensure_images(["filesystem", "sentinel"], store) == []


def test_a_build_failure_propagates():
    store = FakeImageStore({}, build_error="network unreachable")

    with pytest.raises(ImageBuildFailed):
        ensure_images(["filesystem"], store)


def test_a_compose_build_stops_at_its_failing_batch_after_the_earlier_ones_built():
    services = [f"server-{index}" for index in range(3 * COMPOSE_BUILD_BATCH_SIZE)]
    failing_batch = services[COMPOSE_BUILD_BATCH_SIZE : 2 * COMPOSE_BUILD_BATCH_SIZE]
    build = given.ScriptedComposeBuild(failing=failing_batch[0])

    failed = compose_build(services, run_batch=build)

    assert build.batches == [services[:COMPOSE_BUILD_BATCH_SIZE], failing_batch]
    assert failed is not None
    assert failed.services == failing_batch


def test_a_compose_build_builds_every_service_in_bounded_batches():
    build = given.ScriptedComposeBuild()
    services = [f"server-{index}" for index in range(3 * COMPOSE_BUILD_BATCH_SIZE + 1)]

    failed = compose_build(services, run_batch=build)

    assert failed is None
    assert sorted(service for batch in build.batches for service in batch) == sorted(services)
    assert all(len(batch) <= COMPOSE_BUILD_BATCH_SIZE for batch in build.batches)


def test_a_service_named_twice_is_built_once():
    build = given.ScriptedComposeBuild()

    compose_build(["app", "app-patched", "app"], run_batch=build)

    assert [service for batch in build.batches for service in batch] == ["app", "app-patched"]


def test_no_service_builds_nothing():
    build = given.ScriptedComposeBuild()

    compose_build([], run_batch=build)

    assert build.batches == []


def test_a_compose_store_build_failure_raises_with_its_services_and_stderr_tail():
    services = [f"server-{index}" for index in range(2 * COMPOSE_BUILD_BATCH_SIZE)]
    failing_batch = services[COMPOSE_BUILD_BATCH_SIZE:]
    build = given.ScriptedComposeBuild(failing=failing_batch[0])

    with pytest.raises(ImageBuildFailed) as raised:
        ComposeImageStore(run_batch=build).build(services)

    assert raised.value.services == tuple(failing_batch)
    assert raised.value.stderr_tail.splitlines()[-1] == build.failure_line()
    assert "step 0\n" not in raised.value.stderr_tail


def test_the_injected_tag_selects_which_namespace_is_read():
    store = FakeImageStore(
        {nuisance_images.image_tag("filesystem"): dockerfile_fingerprint("filesystem")}
    )

    assert stale_services(["filesystem"], store, tag=nuisance_images.image_tag) == []
    assert stale_services(["filesystem"], store) == ["filesystem"]


def test_a_comment_or_a_blank_line_leaves_the_fingerprint_unchanged(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile.demo"
    dockerfile.write_text("FROM node:22\nRUN npm install demo\n")
    before = dockerfile_fingerprint("demo", tmp_path)

    dockerfile.write_text("# pinned\nFROM node:22\n\n  # the server\nRUN npm install demo\n")

    assert dockerfile_fingerprint("demo", tmp_path) == before


def test_changing_an_instruction_moves_the_fingerprint(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile.demo"
    dockerfile.write_text("FROM node:22\nRUN npm install demo@1.0.0\n")
    before = dockerfile_fingerprint("demo", tmp_path)

    dockerfile.write_text("FROM node:22\nRUN npm install demo@1.0.1\n")

    assert dockerfile_fingerprint("demo", tmp_path) != before


def test_a_base_named_by_tag_only_is_unpinned():
    assert unpinned_bases(["FROM node:22-bookworm-slim"]) == ["node:22-bookworm-slim"]


def test_a_base_named_by_tag_and_digest_is_pinned():
    assert unpinned_bases([f"FROM node:22-bookworm-slim@{DIGEST}"]) == []


def test_a_base_named_by_digest_without_tag_is_pinned():
    assert unpinned_bases([f"FROM node@{DIGEST}"]) == []


def test_a_platform_flag_and_a_stage_name_leave_the_bare_reference():
    instructions = ["FROM --platform=linux/amd64 python:3.12-slim AS build"]

    assert unpinned_bases(instructions) == ["python:3.12-slim"]


def test_a_reference_to_an_earlier_stage_needs_no_digest():
    instructions = [
        f"FROM golang:1.25-alpine@{DIGEST} AS build",
        "RUN go build ./...",
        "FROM build",
        "FROM alpine:3.20",
    ]

    assert unpinned_bases(instructions) == ["alpine:3.20"]


def test_a_lower_case_from_is_read():
    assert unpinned_bases(["from node:20"]) == ["node:20"]


def test_scratch_needs_no_digest():
    assert unpinned_bases(["FROM scratch"]) == []


def test_a_build_argument_reference_is_unpinned():
    assert unpinned_bases(["FROM ${BASE}"]) == ["${BASE}"]


def test_a_digest_of_the_wrong_length_is_unpinned():
    assert unpinned_bases(["FROM node:20@sha256:abc"]) == ["node:20@sha256:abc"]
