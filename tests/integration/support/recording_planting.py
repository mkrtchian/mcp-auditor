import subprocess
from collections.abc import Sequence
from typing import override

from evals.cve.planting import DockerPlanting


class RecordingPlanting(DockerPlanting):
    def __init__(self) -> None:
        self.networks: list[str] = []
        self.containers: list[str] = []
        self.holders: list[str] = []
        self.stand_ins: list[str] = []

    @override
    def create_network(self) -> str:
        name = super().create_network()
        self.networks.append(name)
        return name

    @override
    def start_holder(self, run_args: Sequence[str]) -> str:
        name = super().start_holder(run_args)
        self.containers.append(name)
        self.holders.append(name)
        return name

    @override
    def start_sentinel(self, run_args: Sequence[str]) -> str:
        name = super().start_sentinel(run_args)
        self.containers.append(name)
        return name

    @override
    def start_stand_in(self, run_args: Sequence[str]) -> str:
        name = super().start_stand_in(run_args)
        self.containers.append(name)
        self.stand_ins.append(name)
        return name


def nothing_it_made_outlives(docker: RecordingPlanting) -> None:
    assert docker.networks and docker.containers
    assert not [name for name in docker.containers if _exists("container", name)]
    assert not [name for name in docker.networks if _exists("network", name)]


def no_container_it_started_outlives(docker: RecordingPlanting) -> None:
    """For a launch with no network of its own: its holder and stand-ins only."""
    assert docker.containers
    assert not [name for name in docker.containers if _exists("container", name)]


def _exists(kind: str, name: str) -> bool:
    result = subprocess.run(["docker", kind, "inspect", name], capture_output=True, text=True)
    return result.returncode == 0
