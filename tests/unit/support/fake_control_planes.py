from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from evals.cve.backends.kubernetes import StoodControlPlane
from evals.cve.backends.kubernetes_detection import ControlPlaneDocker

API_SERVER = "https://192.0.2.10:6443"
ADMIN_CONF = (
    f"apiVersion: v1\nclusters:\n- cluster:\n    server: {API_SERVER}\n  name: kubernetes\n"
)


class FakeControlPlane:
    """Stands a control plane on a named network with a kubeconfig file, and records each
    stand-up and the network it yields."""

    def __init__(self, kubeconfig: Path) -> None:
        self.kubeconfig = kubeconfig
        self.stood: list[str] = []
        self.networks: list[str] = []
        self.connected: list[tuple[str, str]] = []

    @contextmanager
    def stand(self, name: str) -> Generator[StoodControlPlane]:
        self.stood.append(name)
        network = f"kube-net-{len(self.stood)}"
        self.networks.append(network)
        yield StoodControlPlane(network, self.kubeconfig)

    def connect(self, network: str, container: str) -> None:
        self.connected.append((network, container))

    def docker(self) -> ControlPlaneDocker:
        return ControlPlaneDocker(self.stand, self.connect)


def a_control_plane(tmp_path: Path) -> FakeControlPlane:
    kubeconfig = tmp_path / "config"
    kubeconfig.write_text(ADMIN_CONF)
    return FakeControlPlane(kubeconfig)
