"""The production `PlantingDocker` port that drives Docker and the host filesystem for planting.

Setup calls run with `check=True` so a failure raises before a launch is yielded. Teardown
calls are best-effort and never raise. Every network and container carries the
`mcp-auditor-cve` label, so an orphan left by a crashed run is swept by label and never
blocks a later launch.
"""

import logging
import os
import secrets
import subprocess
import tempfile
import time
from collections.abc import Sequence

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

# Generous enough for a healthy sentinel under concurrency, and to wait out httpd start-up:
# paid in full only on a real failure, since a serving sentinel answers on an early retry.
_SENTINEL_PROBE_BUDGET = 15.0
_SENTINEL_PROBE_INTERVAL = 0.2
# Bounds one fetch both on the host (the `docker exec` client) and inside the sentinel (busybox
# `wget`, which otherwise waits 900 s and outlives a killed client).
_SENTINEL_FETCH_TIMEOUT = 5.0


def _best_effort(*command: str) -> None:
    try:
        result = subprocess.run(list(command), check=False, capture_output=True, text=True)
    except OSError as error:
        logger.warning("cleanup command failed: %s (%s)", " ".join(command), error)
        return
    if result.returncode != 0:
        logger.warning("cleanup command failed: %s (%s)", " ".join(command), result.stderr.strip())


class DockerPlanting(PlantingDocker):
    """Drives Docker and the host filesystem, labelling every network and container it makes."""

    def image_accounts(self, image_tag: str) -> ImageAccounts:
        return ImageAccounts(
            self._read(image_tag, "/etc/passwd"), self._read(image_tag, "/etc/group")
        )

    def write_host_file(self, content: str, mode: int) -> str:
        descriptor, path = tempfile.mkstemp(prefix=f"{LABEL}-")
        try:
            with os.fdopen(descriptor, "w") as handle:
                handle.write(content)
            os.chmod(path, mode)
        except BaseException:
            os.unlink(path)
            raise
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
        _best_effort("docker", "network", "rm", name)

    def start_holder(self, run_args: Sequence[str]) -> str:
        return self._run_detached(run_args)

    def remove_holder(self, name: str) -> None:
        _best_effort("docker", "rm", "-f", name)

    def start_sentinel(self, run_args: Sequence[str]) -> str:
        return self._run_detached(run_args)

    def remove_sentinel(self, name: str) -> None:
        _best_effort("docker", "rm", "-f", name)

    def sentinel_body(self, name: str, host: str, request_target: str) -> str | None:
        deadline = time.monotonic() + _SENTINEL_PROBE_BUDGET
        url = f"http://{host}:80{request_target}"
        while True:
            body = self._fetch(name, url)
            if body is not None or time.monotonic() >= deadline:
                return body
            time.sleep(_SENTINEL_PROBE_INTERVAL)

    def _fetch(self, name: str, url: str) -> str | None:
        try:
            result = subprocess.run(
                ["docker", "exec", name, "wget", "-T", f"{_SENTINEL_FETCH_TIMEOUT:g}", "-qO-", url],
                check=False,
                capture_output=True,
                text=True,
                timeout=_SENTINEL_FETCH_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return result.stdout if result.returncode == 0 else None

    def run_address_setup(self, run_args: Sequence[str]) -> None:
        subprocess.run(
            ["docker", "run", "--rm", "--label", LABEL, *run_args], check=True, capture_output=True
        )

    def _read(self, image_tag: str, path: str) -> str:
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--label",
                LABEL,
                *confinement_args(),
                "--entrypoint",
                "cat",
                image_tag,
                path,
            ],
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
