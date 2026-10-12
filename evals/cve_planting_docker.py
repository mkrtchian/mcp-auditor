"""The production `PlantingDocker` port and the two context-manager helpers the per-target
environments still enter directly.

Setup calls run with `check=True` so a failure raises before a launch is yielded; teardown
calls are best-effort and never raise. Every network and container carries the
`mcp-auditor-cve` label, so an orphan left by a crashed run is swept by label and never
blocks a later launch.
"""

import logging
import os
import secrets
import subprocess
import tempfile
from collections.abc import Generator, Sequence
from contextlib import contextmanager

from evals.cve_planting_base import (
    LABEL,
    ImageAccounts,
    PlantingDocker,
    confinement_args,
    quiet,
)
from evals.cve_planting_base import (
    SENTINEL_IMAGE as SENTINEL_IMAGE,
)

logger = logging.getLogger(__name__)


def best_effort(*command: str) -> None:
    try:
        result = subprocess.run(list(command), check=False, capture_output=True, text=True)
    except OSError as error:
        logger.warning("cleanup command failed: %s (%s)", " ".join(command), error)
        return
    if result.returncode != 0:
        logger.warning("cleanup command failed: %s (%s)", " ".join(command), result.stderr.strip())


@contextmanager
def docker_network() -> Generator[str]:
    name = f"{LABEL}-{secrets.token_hex(6)}"
    subprocess.run(
        ["docker", "network", "create", "--label", LABEL, name], check=True, capture_output=True
    )
    try:
        yield name
    finally:
        best_effort("docker", "network", "rm", name)


@contextmanager
def sidecar(image: str, *run_args: str) -> Generator[str]:
    name = f"{LABEL}-{secrets.token_hex(6)}"
    command = ["docker", "run", "-d", "--rm", *confinement_args(), "--label", LABEL, "--name", name]
    subprocess.run([*command, *run_args, image], check=True, capture_output=True)
    try:
        yield name
    finally:
        best_effort("docker", "stop", name)


class DockerPlanting(PlantingDocker):
    """Drives Docker and the host filesystem, labelling every network and container it makes."""

    def image_accounts(self, image_tag: str) -> ImageAccounts:
        return ImageAccounts(
            self._read(image_tag, "/etc/passwd"), self._read(image_tag, "/etc/group")
        )

    def write_host_file(self, content: str, mode: int) -> str:
        descriptor, path = tempfile.mkstemp(prefix=f"{LABEL}-")
        with os.fdopen(descriptor, "w") as handle:
            handle.write(content)
        os.chmod(path, mode)
        return path

    def remove_host_file(self, path: str) -> None:
        quiet(os.unlink, path)

    def create_network(self) -> str:
        name = f"{LABEL}-{secrets.token_hex(6)}"
        subprocess.run(
            ["docker", "network", "create", "--label", LABEL, name], check=True, capture_output=True
        )
        return name

    def remove_network(self, name: str) -> None:
        best_effort("docker", "network", "rm", name)

    def start_holder(self, run_args: Sequence[str]) -> str:
        return self._run_detached(run_args)

    def remove_holder(self, name: str) -> None:
        best_effort("docker", "rm", "-f", name)

    def start_sentinel(self, run_args: Sequence[str]) -> str:
        return self._run_detached(run_args)

    def stop_sentinel(self, name: str) -> None:
        best_effort("docker", "stop", name)

    def run_address_setup(self, run_args: Sequence[str]) -> None:
        subprocess.run(
            ["docker", "run", "--rm", "--label", LABEL, *run_args], check=True, capture_output=True
        )

    def _read(self, image_tag: str, path: str) -> str:
        result = subprocess.run(
            ["docker", "run", "--rm", *confinement_args(), "--entrypoint", "cat", image_tag, path],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout

    def _run_detached(self, run_args: Sequence[str]) -> str:
        name = f"{LABEL}-{secrets.token_hex(6)}"
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--label", LABEL, "--name", name, *run_args],
            check=True,
            capture_output=True,
        )
        return name
