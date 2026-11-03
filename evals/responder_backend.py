"""The lifecycle shared by the light HTTP responder backends (CKAN, ContextForge).

A responder is a singleton container on a fixed public-range IP of its own closed labeled bridge
(no route to the host or the Internet), stood once and reused across a server's concurrent nuisance
runs, reaped by the generic orphan sweep.

The server argv and the singleton both carry the nuisance confinement, memory bound included (the
singleton also when a fix check ensures it), while a fix check's own per-launch responder container
keeps the acceptance confinement.
"""

import subprocess
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from evals.closed_network import ensure_closed_network
from evals.cve_planting_base import LABEL, PlantingHost
from evals.docker_paths import DOCKER_DIRECTORY
from evals.nuisance_confinement import nuisance_confinement_args, running_with_bound, user_args


@dataclass(frozen=True)
class Responder:
    image: str
    container: str
    bridge: str
    subnet: str
    ip: str
    dockerfile: Path
    run_args: tuple[str, ...] = ()  # extra arguments of the singleton's own `docker run`

    def server_args(
        self,
        name: str,
        image: str,
        host: PlantingHost,
        server_launch: Sequence[str],
        extra_args: Sequence[str] = (),
    ) -> list[str]:
        return [
            "run", "-i", "--rm",
            *nuisance_confinement_args(),
            "--name", name,
            "--label", LABEL,
            "--network", self.bridge,
            *extra_args,
            *user_args(host.user),
            "-w", host.working_directory,
            image,
            *server_launch,
        ]  # fmt: skip

    def singleton_run_args(self) -> list[str]:
        return [
            "run", "-d",
            "--name", self.container,
            "--label", LABEL,
            "--network", self.bridge,
            "--ip", self.ip,
            *nuisance_confinement_args(),
            "--cap-add", "NET_BIND_SERVICE",  # root behind cap-drop ALL still binds 80/443
            *self.run_args,
            self.image,
        ]  # fmt: skip

    def ensure(self) -> None:
        self._ensure_image()
        ensure_closed_network(self.bridge, "--subnet", self.subnet)
        if not running_with_bound(self.container):
            if self._exists():
                remove(self.container)
            _run("docker", *self.singleton_run_args())

    def _ensure_image(self) -> None:
        present = _run("docker", "image", "inspect", self.image, check=False)
        if present.returncode != 0:
            _run(
                "docker", "build", "-t", self.image, "-f", str(self.dockerfile),
                str(DOCKER_DIRECTORY), timeout=600.0,
            )  # fmt: skip

    def _exists(self) -> bool:
        return self.container in self._names("docker", "ps", "-a")

    def _names(self, *ps_command: str) -> list[str]:
        result = _run(
            *ps_command,
            "--filter", f"name=^{self.container}$", "--format", "{{.Names}}", check=False,
        )  # fmt: skip
        return result.stdout.split()


def remove(name: str) -> None:
    with suppress(subprocess.SubprocessError, OSError):
        _run("docker", "rm", "-f", name, check=False)


def _run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)
