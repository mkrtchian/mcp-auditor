from collections.abc import Generator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass

from evals.cve.backends.backend_beside_launch import BackendStand, launch_beside_backend
from evals.cve.environments import Launch, LaunchShape
from evals.cve.planting import PlantingSpec
from tests.fakes.planting_docker import FakePlantingDocker

BACKEND_NETWORK = "backend-net"
BACKEND_MOUNT = "/backend/config"


@dataclass(frozen=True)
class StoodFakeBackend:
    network: str

    def mount_args(self) -> list[str]:
        return ["-v", f"{BACKEND_MOUNT}:{BACKEND_MOUNT}:ro"]


class FakeBackendStand:
    """Stands a backend on a named network, and records the containers connected to it and the
    holders still running when it is removed."""

    def __init__(self, planting: FakePlantingDocker) -> None:
        self.planting = planting
        self.connected: list[tuple[str, str]] = []
        self.holders_at_removal: list[list[str]] = []

    @contextmanager
    def stand(self) -> Generator[StoodFakeBackend]:
        yield StoodFakeBackend(BACKEND_NETWORK)
        self.holders_at_removal.append(list(self.planting.holders))

    def connect(self, network: str, container: str) -> None:
        self.connected.append((network, container))


def a_launch_beside(
    backend: FakeBackendStand, spec: PlantingSpec
) -> AbstractContextManager[Launch]:
    return launch_beside_backend(
        "img",
        spec,
        LaunchShape.NORMAL,
        docker=backend.planting,
        backend=BackendStand(backend.stand, backend.connect),
    )
