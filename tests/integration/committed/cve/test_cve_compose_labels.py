from pathlib import Path
from typing import Any

import pytest
import yaml

from evals.cve.docker_paths import DOCKER_DIRECTORY
from evals.cve.fixture_sources import unsourced_copies
from evals.cve.images import (
    COMPOSE_FILE,
    FINGERPRINT_LABEL,
    dockerfile_fingerprint,
    dockerfile_instructions,
    unpinned_bases,
)

COMPOSE_SERVICES: dict[str, Any] = yaml.safe_load(COMPOSE_FILE.read_text())["services"]


@pytest.mark.parametrize("service", sorted(COMPOSE_SERVICES))
def test_each_compose_service_is_labeled_with_its_dockerfile_fingerprint(service: str):
    expected = dockerfile_fingerprint(service)
    labels = COMPOSE_SERVICES[service]["build"].get("labels", {})

    assert labels.get(FINGERPRINT_LABEL) == expected, (
        f'{service}: set build.labels.{FINGERPRINT_LABEL} to "{expected}" in {COMPOSE_FILE}'
    )


@pytest.mark.parametrize(
    "dockerfile", sorted(DOCKER_DIRECTORY.glob("Dockerfile.*")), ids=lambda path: path.name
)
def test_no_dockerfile_copies_from_the_build_context(dockerfile: Path):
    unsourced = unsourced_copies(dockerfile_instructions(dockerfile))

    assert unsourced == [], f"{dockerfile.name}: the fingerprint would miss {unsourced}"


@pytest.mark.parametrize(
    "dockerfile", sorted(DOCKER_DIRECTORY.glob("Dockerfile.*")), ids=lambda path: path.name
)
def test_every_base_image_is_pinned_by_digest(dockerfile: Path):
    unpinned = unpinned_bases(dockerfile_instructions(dockerfile))

    assert not unpinned, f"{dockerfile.name}: pin {unpinned} to image:tag@sha256:<digest>"
