from pathlib import Path

import pytest

from evals.cve.backends.kubernetes import READY_LINE
from evals.cve.planting_base import PlantingHost, SymbolicUser
from tests.fakes import CLOSED_NETWORK_INSPECT, ScriptedDockerExecutable
from tests.unit.support.fake_control_planes import ADMIN_CONF


def a_host() -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)


def a_docker_whose_control_plane_comes_up(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> ScriptedDockerExecutable:
    answers: dict[tuple[str, ...], str] = {
        ("network", "inspect"): CLOSED_NETWORK_INSPECT,
        ("logs",): f'[certs] Generating "ca" certificate and key\n{READY_LINE}\n',
        ("inspect",): "running\n",
        ("exec",): ADMIN_CONF,
    }
    return ScriptedDockerExecutable(answers).installed(monkeypatch, tmp_path)
