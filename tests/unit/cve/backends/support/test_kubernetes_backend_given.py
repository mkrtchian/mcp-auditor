from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest

from evals.cve.backends.kubernetes import READY_LINE, StoodControlPlane
from evals.cve.backends.kubernetes_detection import ControlPlaneDocker
from evals.cve.planting_base import PlantingHost, SymbolicUser
from tests.fakes import CLOSED_NETWORK_INSPECT, ScriptedDocker
from tests.fakes.planting_docker import FakePlantingDocker

API_SERVER = "https://192.0.2.10:6443"
ADMIN_CONF = (
    f"apiVersion: v1\nclusters:\n- cluster:\n    server: {API_SERVER}\n  name: kubernetes\n"
)


def a_host() -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)


def a_docker_whose_control_plane_comes_up(monkeypatch: pytest.MonkeyPatch) -> ScriptedDocker:
    answers = {
        ("network", "inspect"): CLOSED_NETWORK_INSPECT,
        ("logs",): f'[certs] Generating "ca" certificate and key\n{READY_LINE}\n',
        ("inspect",): "running\n",
        ("exec",): ADMIN_CONF,
    }
    return ScriptedDocker(answers).installed(monkeypatch)


class FakeControlPlane:
    """Stands a control plane on a named network with a kubeconfig file, and records the
    containers connected to that network."""

    def __init__(self, kubeconfig: Path, planting: FakePlantingDocker | None = None) -> None:
        self.kubeconfig = kubeconfig
        self.planting = planting
        self.stood: list[str] = []
        self.connected: list[tuple[str, str]] = []
        self.holders_at_removal: list[list[str]] = []

    @contextmanager
    def stand(self, name: str) -> Generator[StoodControlPlane]:
        self.stood.append(name)
        yield StoodControlPlane(f"kube-net-{len(self.stood)}", self.kubeconfig)
        if self.planting is not None:
            self.holders_at_removal.append(list(self.planting.holders))

    def connect(self, network: str, container: str) -> None:
        self.connected.append((network, container))

    def docker(self) -> ControlPlaneDocker:
        return ControlPlaneDocker(self.stand, self.connect)


def a_control_plane(tmp_path: Path) -> FakeControlPlane:
    kubeconfig = tmp_path / "config"
    kubeconfig.write_text(ADMIN_CONF)
    return FakeControlPlane(kubeconfig)


def a_control_plane_watching_holders(
    tmp_path: Path, planting: FakePlantingDocker
) -> FakeControlPlane:
    control_plane = a_control_plane(tmp_path)
    control_plane.planting = planting
    return control_plane
