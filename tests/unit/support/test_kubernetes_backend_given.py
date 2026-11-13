import json
import subprocess
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from pathlib import Path

import pytest

from evals.cve.backends.kubernetes import READY_LINE, StoodControlPlane
from evals.cve.backends.kubernetes_detection import ControlPlaneDocker
from evals.cve.planting import RANDOM_NONCES, PlantingSpec, planting_spec
from evals.cve.planting_base import LABEL, PlantingHost, SymbolicUser
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.test_cve_planting_given import endpoint_place

API_SERVER = "https://192.0.2.10:6443"
ADMIN_CONF = (
    f"apiVersion: v1\nclusters:\n- cluster:\n    server: {API_SERVER}\n  name: kubernetes\n"
)


def a_host() -> PlantingHost:
    return PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)


class FakeControlPlaneDocker:
    """Answers every Docker command with success: a network it was asked to create inspects as
    closed, the control plane runs and logs its ready line, and its admin.conf reads as
    ADMIN_CONF."""

    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def run(self, args: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        command = list(args)
        self.commands.append(command)
        return subprocess.CompletedProcess(command, 0, self._stdout(command), "")

    def _stdout(self, command: list[str]) -> str:
        match command[1:]:
            case ["network", "inspect", *_]:
                return _a_closed_network()
            case ["logs", *_]:
                return f'[certs] Generating "ca" certificate and key\n{READY_LINE}\n'
            case ["inspect", *_]:
                return "running\n"
            case ["exec", _, "cat", _]:
                return ADMIN_CONF
            case _:
                return ""

    def started(self) -> list[list[str]]:
        return [command for command in self.commands if command[1:3] == ["run", "-d"]]

    def created_networks(self) -> list[str]:
        return [command[-1] for command in self.commands if command[1:3] == ["network", "create"]]

    def removed(self) -> list[str]:
        removals = (["rm", "-f", "-v"], ["network", "rm"])
        return [
            command[-1]
            for command in self.commands
            if any(command[1 : 1 + len(removal)] == removal for removal in removals)
        ]


def _a_closed_network() -> str:
    return json.dumps(
        {
            "Internal": True,
            "EnableIPv6": False,
            "Labels": {LABEL: ""},
            "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
            "Containers": {},
        }
    )


def a_docker_whose_control_plane_comes_up(
    monkeypatch: pytest.MonkeyPatch,
) -> FakeControlPlaneDocker:
    docker = FakeControlPlaneDocker()
    monkeypatch.setattr(subprocess, "run", docker.run)
    return docker


class FakeControlPlane:
    """Stands a control plane on a named network with a kubeconfig file, and records the
    containers connected to that network."""

    def __init__(self, kubeconfig: Path, planting: FakePlantingDocker | None = None) -> None:
        self.kubeconfig = kubeconfig
        self.planting = planting
        self.stood: list[str] = []
        self.connected: list[tuple[str, str]] = []
        self.holders_at_removal: list[list[str]] = []
        self.memory_bounds: list[tuple[str, ...]] = []

    @contextmanager
    def stand(self, name: str, memory_bound: Sequence[str]) -> Generator[StoodControlPlane]:
        self.stood.append(name)
        self.memory_bounds.append(tuple(memory_bound))
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


def a_spec_with_a_holder() -> PlantingSpec:
    # A link-local endpoint is bound inside a namespace holder the server joins.
    place = endpoint_place(host="169.254.169.254", path="/latest/meta-data/")
    spec = planting_spec((place,), a_host(), RANDOM_NONCES)
    assert spec.needs_holder
    return spec


def a_spec_without_a_holder() -> PlantingSpec:
    spec = planting_spec((), a_host(), RANDOM_NONCES)
    assert not spec.needs_holder
    return spec


def a_spec_with_no_network() -> PlantingSpec:
    return planting_spec(
        (), PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False), RANDOM_NONCES
    )
