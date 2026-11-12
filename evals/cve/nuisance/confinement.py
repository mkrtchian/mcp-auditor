"""The container options every nuisance server runs with (nuisance suite rule v3, Eligibility, The
real software): the confinement of the detection suite plus the memory bound, which only the
nuisance suite sets, on its server containers and on every backend container (the shared Doris
cluster included). A persistent backend container carries the digest of its launch, so one started
with another launch is recreated once.

A server with no backend runs with no network. When its admission declares public names, the hosts
it needs are served under their real names the way a detection launch serves them (ADR 034): the
planting code stands a namespace holder and the stand-ins, plants nothing, and the server joins the
holder's network namespace with the trust setting.
"""

import hashlib
import json
import subprocess
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from evals.cve.planting import RANDOM_NONCES, planted, planting_spec
from evals.cve.planting_base import (
    LABEL,
    PlantingDocker,
    PlantingHost,
    SymbolicUser,
    confinement_args,
    no_network_args,
    unprivileged_user_args,
)
from evals.cve.planting_docker import DOCKER_PLANTING
from evals.cve.public_stand_ins import STAND_INS_DIRECTORY

# arcadedb's fixed 2 GiB ZGC heap plus an audit's load; the product's regime uses 2g (ADR 018)
MEMORY_BOUND = "4g"
LAUNCH_LABEL = f"{LABEL}-launch"


def memory_bound_args() -> list[str]:
    # --memory-swap equal to --memory, so the bound bites: Docker otherwise grants as much swap
    # again.
    return ["--memory", MEMORY_BOUND, "--memory-swap", MEMORY_BOUND]


def nuisance_confinement_args() -> list[str]:
    return [*confinement_args(), *memory_bound_args()]


def labelled_run_args(run_args: Sequence[str]) -> list[str]:
    if list(run_args[:2]) != ["run", "-d"]:
        raise ValueError(f"not a `docker run -d` argv: {list(run_args[:2])}")
    return ["run", "-d", "--label", f"{LAUNCH_LABEL}={launch_digest(run_args)}", *run_args[2:]]


def running_with_launch(container: str, run_args: Sequence[str]) -> bool:
    inspected = subprocess.run(
        [
            "docker", "inspect", "-f",
            f'{{{{.State.Running}}}} {{{{index .Config.Labels "{LAUNCH_LABEL}"}}}}',
            container,
        ],
        capture_output=True,
        text=True,
        check=False,
    )  # fmt: skip
    return inspected.returncode == 0 and launch_matches(inspected.stdout, run_args)


def launch_matches(inspected: str, run_args: Sequence[str]) -> bool:
    # A container started before the launch label prints an empty label: `true` alone.
    return inspected.strip() == f"true {launch_digest(run_args)}"


def launch_digest(run_args: Sequence[str]) -> str:
    return hashlib.sha256(json.dumps(list(run_args)).encode()).hexdigest()


def user_args(user: SymbolicUser) -> list[str]:
    match user:
        case SymbolicUser.UNPRIVILEGED:
            return unprivileged_user_args()


@contextmanager
def single_container_launch_args(
    image: str,
    host: PlantingHost,
    server_launch: Sequence[str],
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
    stand_ins_directory: Path = STAND_INS_DIRECTORY,
) -> Generator[list[str]]:
    if not host.public_names.stand_ins:
        yield single_container_run_args(image, host, server_launch)
        return
    # A nuisance server's `/work` is its project, baked into its image, never the detection
    # suite's tmpfs.
    spec = planting_spec((), replace(host, baked_work=True), RANDOM_NONCES)
    with planted(spec, image, docker, stand_ins_directory) as args:
        yield [
            "run",
            "-i",
            "--rm",
            *nuisance_confinement_args(),
            *args.run_args(),
            image,
            *server_launch,
        ]


def single_container_run_args(
    image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return [
        "run", "-i", "--rm",
        *nuisance_confinement_args(),
        *user_args(host.user),
        "-w", host.working_directory,
        *no_network_args(),
        image,
        *server_launch,
    ]  # fmt: skip
