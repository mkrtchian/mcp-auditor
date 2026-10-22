"""The identity of the images built from evals/docker/: a label carrying the fingerprint of
the Dockerfile's instructions, written in compose.yml, read back on each tag to tell a current
image from a stale or foreign one, which is then rebuilt through compose."""

import hashlib
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol

from evals.cve_targets import DOCKER_DIRECTORY, image_dockerfile, image_tag

FINGERPRINT_LABEL = "org.mcp-auditor.dockerfile-fingerprint"
COMPOSE_FILE = DOCKER_DIRECTORY / "compose.yml"
_STDERR_TAIL_LINES = 20


class ImageBuildFailed(Exception):
    def __init__(self, services: Sequence[str], stderr_tail: str):
        super().__init__(f"docker compose build {' '.join(services)} failed:\n{stderr_tail}")
        self.services = tuple(services)
        self.stderr_tail = stderr_tail


class ImageStore(Protocol):
    def label(self, tag: str, key: str) -> str | None: ...  # None when absent or unlabeled

    def build(self, services: Sequence[str]) -> None: ...  # raises ImageBuildFailed


def ensure_images(
    services: Sequence[str], store: ImageStore, tag: Callable[[str], str] = image_tag
) -> list[str]:
    stale = stale_services(services, store, tag)
    if stale:
        store.build(stale)
    return stale


def stale_services(
    services: Sequence[str], store: ImageStore, tag: Callable[[str], str] = image_tag
) -> list[str]:
    return [
        service
        for service in dict.fromkeys(services)
        if store.label(tag(service), FINGERPRINT_LABEL) != dockerfile_fingerprint(service)
    ]


def dockerfile_fingerprint(service: str, docker_directory: Path = DOCKER_DIRECTORY) -> str:
    instructions = dockerfile_instructions(image_dockerfile(service, docker_directory))
    return hashlib.sha256("\n".join(instructions).encode()).hexdigest()


def dockerfile_instructions(path: Path) -> list[str]:
    lines = (line.strip() for line in path.read_text().splitlines())
    return [line for line in lines if line and not line.startswith("#")]


class ComposeImageStore:
    def label(self, tag: str, key: str) -> str | None:
        command = [
            "docker",
            "image",
            "inspect",
            "--format",
            f'{{{{index .Config.Labels "{key}"}}}}',
        ]
        try:
            result = subprocess.run([*command, tag], capture_output=True, text=True)
        except OSError:
            return None
        value = result.stdout.strip()
        return value if result.returncode == 0 and value else None

    def build(self, services: Sequence[str]) -> None:
        command = ["docker", "compose", "-f", str(COMPOSE_FILE), "build", *services]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            tail = "\n".join(result.stderr.splitlines()[-_STDERR_TAIL_LINES:])
            raise ImageBuildFailed(services, tail)
