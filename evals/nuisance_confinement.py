"""The container options every nuisance server runs with (rule v3, Eligibility, The real
software): the acceptance and holdout confinement plus the memory bound, which only the nuisance
suite sets, on its server containers and on every backend container (the shared Doris cluster
included)."""

import subprocess
from collections.abc import Sequence

from evals.cve_planting_base import (
    PlantingHost,
    SymbolicUser,
    confinement_args,
    host_user_args,
    no_network_args,
    unprivileged_user_args,
)

# arcadedb's fixed 2 GiB ZGC heap plus an audit's load; the product's regime uses 2g (ADR 018)
MEMORY_BOUND = "4g"
MEMORY_BOUND_BYTES = 4 * 1024**3


def memory_bound_args() -> list[str]:
    # --memory-swap equal to --memory, so the bound bites: Docker otherwise grants as much swap
    # again.
    return ["--memory", MEMORY_BOUND, "--memory-swap", MEMORY_BOUND]


def nuisance_confinement_args() -> list[str]:
    return [*confinement_args(), *memory_bound_args()]


def carries_memory_bound(inspected_memory: str) -> bool:
    return inspected_memory.strip() == str(MEMORY_BOUND_BYTES)


def running_with_bound(container: str) -> bool:
    inspected = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}} {{.HostConfig.Memory}}", container],
        capture_output=True,
        text=True,
        check=False,
    )
    if inspected.returncode != 0:
        return False
    running, _, memory = inspected.stdout.strip().partition(" ")
    return running == "true" and carries_memory_bound(memory)


def user_args(user: SymbolicUser) -> list[str]:
    match user:
        case SymbolicUser.HOST:
            return host_user_args()
        case SymbolicUser.UNPRIVILEGED:
            return unprivileged_user_args()


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
