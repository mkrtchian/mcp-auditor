from pathlib import Path

import pytest

from evals.cve.backends.node_sandbox_engine import ENGINE_SOCKET_DIRECTORY
from evals.cve.planting_base import PlantingHost, SymbolicUser
from tests.fakes import ScriptedDockerExecutable

ENGINE_SOCKET = f"{ENGINE_SOCKET_DIRECTORY}/docker.sock"


def a_host() -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)


def a_docker_whose_engine_opens_its_socket(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> ScriptedDockerExecutable:
    docker = ScriptedDockerExecutable({}, opens_socket_at=ENGINE_SOCKET)
    return docker.installed(monkeypatch, tmp_path)
