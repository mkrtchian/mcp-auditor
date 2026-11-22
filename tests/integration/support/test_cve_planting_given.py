import secrets
import subprocess
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import override

from evals.cve.closed_network import create_closed_network
from evals.cve.places import Coordinates, Place, PlaceKind
from evals.cve.planting import (
    RANDOM_NONCES,
    DockerPlanting,
    PlantedArgs,
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    confinement_args,
    planting_spec,
)
from evals.cve.planting_base import LABEL, MEMORY_BOUND, SENTINEL_IMAGE
from evals.cve.planting_spec import request_target
from mcp_auditor.adapters.docker import DockerRuntime

# Docker reads the `g` suffix as 1024³ bytes.
MEMORY_BOUND_BYTES = int(MEMORY_BOUND.removesuffix("g")) * 1024**3
IP_LITERAL = "198.51.100.5"  # RFC 5737 documentation range: routes nowhere
# wget's own 5 s bound plus the start-up of the fresh container each read runs in.
_READ_TIMEOUT = 10.0


DANGLING_LINK = "leak/report"


def a_tree_holding_a_dangling_absolute_link(root: Path) -> None:
    (root / "leak").mkdir(parents=True)
    (root / DANGLING_LINK).symlink_to("/nowhere/in/the/helper")


def missing_prerequisite() -> str | None:
    if not DockerRuntime().available():
        return "CVE planting needs Docker"
    return None


@dataclass(frozen=True)
class SilentListener:
    network: str
    name: str


@contextmanager
def a_listener_that_accepts_and_never_answers() -> Generator[SilentListener]:
    """On a closed network of its own: `sleep` holds `nc`'s stdin open, since busybox `nc`
    half-closes the connection on stdin's end-of-file, which would end the probe at once."""
    listener = SilentListener(f"{LABEL}-{secrets.token_hex(6)}", f"{LABEL}-{secrets.token_hex(6)}")
    create_closed_network(listener.network)
    try:
        subprocess.run(
            [
                "docker", "run", "-d", "--rm", "--label", LABEL, "--name", listener.name,
                "--network", listener.network, "--entrypoint", "/bin/sh", SENTINEL_IMAGE,
                "-c", "sleep 3600 | nc -l -p 80",
            ],
            check=True, capture_output=True, timeout=_READ_TIMEOUT,
        )  # fmt: skip
        yield listener
    finally:
        subprocess.run(["docker", "rm", "-f", listener.name], capture_output=True)
        subprocess.run(["docker", "network", "rm", listener.network], capture_output=True)


def labelled_probe_args(network: str) -> tuple[list[str], str]:
    """Target arguments carrying a label of the test's own, and that `key=value` label."""
    label = f"mcp-auditor-probe-test={secrets.token_hex(6)}"
    return ["--network", network, "--label", label], label


def host_search_domain_reaches_a_plain_container() -> bool:
    """Whether a container started without the resolver option reads a search domain, which
    the host's resolver configuration hands it."""
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--label",
            LABEL,
            "--network",
            "none",
            "--entrypoint",
            "/bin/cat",
            SENTINEL_IMAGE,
            "/etc/resolv.conf",
        ],
        capture_output=True,
        text=True,
        timeout=_READ_TIMEOUT,
        check=True,
    )
    return any(line.startswith("search") for line in result.stdout.splitlines())


def a_work_spec(*, with_an_account: bool) -> PlantingSpec:
    places = [_place("account-1", Coordinates(PlaceKind.ACCOUNT))] if with_an_account else []
    planting_host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/work", False)
    return planting_spec(places, planting_host, RANDOM_NONCES)


def a_launch_of_shape(shape: str) -> PlantingSpec:
    if shape == "no_network":
        planting_host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv/fictional", False)
        return planting_spec([], planting_host, RANDOM_NONCES)
    if shape == "holder":
        return spec_of(IP_LITERAL, "/fict/secret", has_network=True)
    return spec_of("meta.fict", "/fict/secret", has_network=True)


def spec_of(
    host: str, path: str, *, has_network: bool = False, file_at: str | None = None
) -> PlantingSpec:
    places: list[Place] = []
    if file_at is not None:
        places.append(_place("file-1", Coordinates(PlaceKind.FILE, path=file_at)))
    places.append(_place("endpoint-1", Coordinates(PlaceKind.HTTP_ENDPOINT, host=host, path=path)))
    planting_host = PlantingHost(SymbolicUser.UNPRIVILEGED, "/srv/fictional", has_network)
    return planting_spec(places, planting_host, RANDOM_NONCES)


def _place(place_id: str, coordinates: Coordinates) -> Place:
    return Place(
        id=place_id,
        family="fictional-family",
        reaches=frozenset({"arbitrary_read"}),
        kind=coordinates.kind,
        coordinates=coordinates,
    )


def read_as_target(args: PlantedArgs, host: str, path: str) -> str:
    url = f"http://{host}:80{request_target(path)}"
    command = TargetCommand(SENTINEL_IMAGE, "/bin/wget", ("-Y", "off", "-qO-", "-T", "5", url))
    try:
        result = run_as_target(args, command, check=False)
    except subprocess.TimeoutExpired:
        return ""
    return result.stdout


def identity_as_target(args: PlantedArgs) -> dict[str, str]:
    """What the target reads of its own identity, each file under its name, from one container
    started with the target's own options."""
    script = "; ".join(
        f"echo '{_SECTION}{name}'; {command}" for name, command in _IDENTITY_READS.items()
    )
    result = run_as_target(args, TargetCommand(SENTINEL_IMAGE, "/bin/sh", ("-c", script)))
    sections = result.stdout.split(_SECTION)[1:]
    return dict(section.split("\n", 1) for section in sections)


def memory_max_as_target(args: PlantedArgs) -> int:
    """The cgroup v2 memory limit a container started with the target's own options reads."""
    command = TargetCommand(SENTINEL_IMAGE, "/bin/cat", ("/sys/fs/cgroup/memory.max",))
    return int(run_as_target(args, command).stdout)


@dataclass(frozen=True)
class InspectedMemoryBound:
    """A container's limits in bytes, as Docker records them."""

    memory: int
    memory_swap: int  # memory plus swap


def inspected_memory_bound(container: str) -> InspectedMemoryBound:
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}}", container],
        capture_output=True,
        text=True,
        timeout=_READ_TIMEOUT,
        check=True,
    )
    memory, memory_swap = result.stdout.split()
    return InspectedMemoryBound(int(memory), int(memory_swap))


@dataclass(frozen=True)
class WorkObservation:
    at_start: str  # `ls -A /work` before the write
    created: bool
    listing: str  # `ls -ld /work` after the write


def work_as_target(args: PlantedArgs) -> WorkObservation:
    """What a container started with the target's own options sees of `/work`, and whether it
    can write a file there."""
    script = (
        f"ls -A /work; echo '{_SECTION}'; touch /work/written && echo created; "
        f"echo '{_SECTION}'; ls -ld /work"
    )
    result = run_as_target(args, TargetCommand(SENTINEL_IMAGE, "/bin/sh", ("-c", script)))
    at_start, created, listing = result.stdout.split(f"{_SECTION}\n")
    return WorkObservation(at_start, created.strip() == "created", listing)


@dataclass(frozen=True)
class TargetCommand:
    image: str
    entrypoint: str
    command: tuple[str, ...]


def run_as_target(
    args: PlantedArgs, command: TargetCommand, *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--label",
            LABEL,
            *confinement_args(),
            *args.run_args(),
            "--entrypoint",
            command.entrypoint,
            command.image,
            *command.command,
        ],
        capture_output=True,
        text=True,
        timeout=_READ_TIMEOUT,
        check=check,
    )


_SECTION = "=== "
_IDENTITY_READS = {
    "hostname": "hostname",
    "/etc/hosts": "cat /etc/hosts",
    "/etc/resolv.conf": "cat /etc/resolv.conf",
    "env": "env",
}


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
