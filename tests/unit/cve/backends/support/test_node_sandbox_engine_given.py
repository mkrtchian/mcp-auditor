import os
import socket
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from evals.cve.backends.node_sandbox_engine import ENGINE_SOCKET_DIRECTORY
from evals.cve.planting_base import PlantingHost, SymbolicUser
from tests.unit.support.docker_argv import mount_of


def a_host() -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)


class FakeEngineDocker:
    """Answers every Docker command with success, and on an engine's `docker run -d` opens a
    unix socket of mode 0666 in the directory mounted at its socket directory, as the engine's
    entrypoint does."""

    def __init__(self) -> None:
        self.started: list[list[str]] = []
        self.commands: list[list[str]] = []
        self.socket_directories: list[Path] = []

    def run(self, args: Sequence[str], **_: object) -> subprocess.CompletedProcess[str]:
        command = list(args)
        self.commands.append(command)
        if command[1:3] == ["run", "-d"]:
            self.started.append(command)
            self._open_socket(Path(mount_of(command, ENGINE_SOCKET_DIRECTORY).split(":")[0]))
        return subprocess.CompletedProcess(command, 0, "", "")

    def _open_socket(self, directory: Path) -> None:
        self.socket_directories.append(directory)
        # A socket path is bounded to about 100 bytes, so it is bound relative to its directory.
        here = Path.cwd()
        os.chdir(directory)
        try:
            with socket.socket(socket.AF_UNIX) as engine_socket:
                engine_socket.bind("docker.sock")
            os.chmod("docker.sock", 0o666)
        finally:
            os.chdir(here)


def a_docker_whose_engine_opens_its_socket(monkeypatch: pytest.MonkeyPatch) -> FakeEngineDocker:
    docker = FakeEngineDocker()
    monkeypatch.setattr(subprocess, "run", docker.run)
    return docker
