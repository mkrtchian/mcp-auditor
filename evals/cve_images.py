"""The identity of the images built from evals/docker/: a label carrying the fingerprint of
the Dockerfile's instructions, written in compose.yml, read back on each tag to tell a current
image from a stale or foreign one, which is then rebuilt through compose."""

import hashlib
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from evals.cve_targets import image_tag
from evals.docker_paths import DOCKER_DIRECTORY, image_dockerfile

FINGERPRINT_LABEL = "org.mcp-auditor.dockerfile-fingerprint"
COMPOSE_FILE = DOCKER_DIRECTORY / "compose.yml"
_STDERR_TAIL_LINES = 20
# One `docker compose build` of some seventy images makes BuildKit abandon one at random with
# "context deadline exceeded", while each builds fine in a small group.
COMPOSE_BUILD_BATCH_SIZE = 8
_PINNED = re.compile(r"@sha256:[0-9a-f]{64}$")


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


def unpinned_bases(instructions: Sequence[str]) -> list[str]:
    """A FROM naming an earlier stage of the same Dockerfile, or `scratch`, pulls nothing and
    needs no digest."""
    stages = {"scratch"}
    unpinned: list[str] = []
    for instruction in instructions:
        words = instruction.split()
        if words[0].upper() != "FROM":
            continue
        reference, stage = _base_and_stage(words[1:])
        if reference not in stages and not _PINNED.search(reference):
            unpinned.append(reference)
        if stage:
            stages.add(stage)
    return unpinned


def _base_and_stage(arguments: list[str]) -> tuple[str, str | None]:
    words = [word for word in arguments if not word.startswith("--")]
    has_stage = len(words) >= 3 and words[1].upper() == "AS"
    return words[0], words[2] if has_stage else None


@dataclass(frozen=True)
class FailedBuild:
    services: list[str]
    stdout: str
    stderr: str


RunBatch = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def compose_build_batch(batch: Sequence[str]) -> subprocess.CompletedProcess[str]:
    command = ["docker", "compose", "-f", str(COMPOSE_FILE), "build", *batch]
    return subprocess.run(command, capture_output=True, text=True)


def compose_build(
    services: Sequence[str], run_batch: RunBatch = compose_build_batch
) -> FailedBuild | None:
    """Builds the deduplicated services batch after batch, in order, and stops at the first
    batch that fails."""
    unique = list(dict.fromkeys(services))
    for start in range(0, len(unique), COMPOSE_BUILD_BATCH_SIZE):
        batch = unique[start : start + COMPOSE_BUILD_BATCH_SIZE]
        result = run_batch(batch)
        if result.returncode != 0:
            return FailedBuild(batch, result.stdout, result.stderr)
    return None


@dataclass(frozen=True)
class ComposeImageStore:
    run_batch: RunBatch = compose_build_batch

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
        failed = compose_build(services, self.run_batch)
        if failed:
            tail = "\n".join(failed.stderr.splitlines()[-_STDERR_TAIL_LINES:])
            raise ImageBuildFailed(failed.services, tail)
