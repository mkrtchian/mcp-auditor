from pathlib import Path

import pytest

from evals.cve_images import ImageBuildFailed, dockerfile_fingerprint, ensure_images
from evals.cve_targets import image_tag
from tests.fakes.image_store import FakeImageStore

FILESYSTEM_TAG = image_tag("filesystem")
SENTINEL_TAG = image_tag("sentinel")


def test_a_tag_carrying_its_dockerfile_fingerprint_is_not_rebuilt():
    current = dockerfile_fingerprint("filesystem")
    store = FakeImageStore({FILESYSTEM_TAG: current})

    rebuilt = ensure_images(["filesystem"], store)

    assert rebuilt == []
    assert store.label_of(FILESYSTEM_TAG) == current


@pytest.mark.parametrize(
    "labels",
    [{}, {FILESYSTEM_TAG: None}, {FILESYSTEM_TAG: dockerfile_fingerprint("fetch")}],
    ids=["absent", "unlabeled", "another-fingerprint"],
)
def test_a_stale_tag_is_rebuilt_with_its_current_fingerprint(labels: dict[str, str | None]):
    store = FakeImageStore(labels)

    rebuilt = ensure_images(["filesystem"], store)

    assert rebuilt == ["filesystem"]
    assert store.label_of(FILESYSTEM_TAG) == dockerfile_fingerprint("filesystem")


def test_only_the_stale_services_are_rebuilt_in_input_order_once_each():
    store = FakeImageStore({FILESYSTEM_TAG: dockerfile_fingerprint("filesystem")})

    rebuilt = ensure_images(["sentinel", "filesystem", "fetch", "sentinel"], store)

    assert rebuilt == ["sentinel", "fetch"]
    for service in ("sentinel", "filesystem", "fetch"):
        assert store.label_of(image_tag(service)) == dockerfile_fingerprint(service)


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
