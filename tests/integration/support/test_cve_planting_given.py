import subprocess
from collections.abc import Sequence

from evals.cve_places import Coordinates, Place, PlantKind
from evals.cve_planting import (
    RANDOM_NONCES,
    DockerPlanting,
    PlantedArgs,
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    planting_spec,
)
from evals.cve_planting_base import SENTINEL_IMAGE
from evals.cve_planting_spec import request_target
from mcp_auditor.adapters.docker import DockerRuntime

IP_LITERAL = "198.51.100.5"  # RFC 5737 documentation range: routes nowhere


def missing_prerequisite() -> str | None:
    if not DockerRuntime().available():
        return "CVE planting needs Docker"
    if not _sentinel_image_present():
        return f"{SENTINEL_IMAGE} absent: docker compose -f evals/docker/compose.yml build"
    return None


def _sentinel_image_present() -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", SENTINEL_IMAGE], capture_output=True, text=True
    )
    return result.returncode == 0


def spec_of(host: str, path: str, *, has_network: bool = False) -> PlantingSpec:
    place = Place(
        id="endpoint-1",
        family="fictional-family",
        reachable_by=frozenset({"arbitrary_read"}),
        kind=PlantKind.HTTP_ENDPOINT,
        coordinates=Coordinates(PlantKind.HTTP_ENDPOINT, host=host, path=path),
    )
    planting_host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv/fictional", has_network)
    return planting_spec([place], planting_host, RANDOM_NONCES)


def read_in_namespace(args: PlantedArgs, host: str, path: str) -> str:
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            *args.network,
            "--entrypoint",
            "wget",
            SENTINEL_IMAGE,
            "-qO-",
            f"http://{host}:80{request_target(path)}",
        ],
        capture_output=True,
        text=True,
    )
    return result.stdout


class RecordingPlanting(DockerPlanting):
    def __init__(self) -> None:
        self.networks: list[str] = []
        self.containers: list[str] = []

    def create_network(self) -> str:
        name = super().create_network()
        self.networks.append(name)
        return name

    def start_holder(self, run_args: Sequence[str]) -> str:
        name = super().start_holder(run_args)
        self.containers.append(name)
        return name

    def start_sentinel(self, run_args: Sequence[str]) -> str:
        name = super().start_sentinel(run_args)
        self.containers.append(name)
        return name
