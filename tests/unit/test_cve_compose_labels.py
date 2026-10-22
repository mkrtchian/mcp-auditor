from pathlib import Path
from typing import Any

import pytest
import yaml

from evals.cve_images import (
    COMPOSE_FILE,
    FINGERPRINT_LABEL,
    dockerfile_fingerprint,
    dockerfile_instructions,
)
from evals.cve_planting_base import SENTINEL_SERVICE
from evals.cve_targets import CVE_TARGETS, DOCKER_DIRECTORY

COMPOSE_SERVICES: dict[str, Any] = yaml.safe_load(COMPOSE_FILE.read_text())["services"]


@pytest.mark.parametrize("service", sorted(COMPOSE_SERVICES))
def test_each_compose_service_is_labeled_with_its_dockerfile_fingerprint(service: str):
    expected = dockerfile_fingerprint(service)
    labels = COMPOSE_SERVICES[service]["build"].get("labels", {})

    assert labels.get(FINGERPRINT_LABEL) == expected, (
        f'{service}: set build.labels.{FINGERPRINT_LABEL} to "{expected}" in {COMPOSE_FILE}'
    )


def test_every_service_a_target_or_the_sentinel_names_is_a_compose_service():
    named = {SENTINEL_SERVICE}
    for target in CVE_TARGETS:
        named |= {*target.images, target.patched_image}

    assert named <= COMPOSE_SERVICES.keys()


@pytest.mark.parametrize(
    "dockerfile", sorted(DOCKER_DIRECTORY.glob("Dockerfile.*")), ids=lambda path: path.name
)
def test_no_dockerfile_copies_from_the_build_context(dockerfile: Path):
    copying = [
        line
        for line in dockerfile_instructions(dockerfile)
        if line.split()[0].upper() in {"COPY", "ADD"}
    ]

    assert copying == [], f"{dockerfile.name}: the fingerprint would miss the copied source"
