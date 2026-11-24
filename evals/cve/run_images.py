"""What both run orchestrators check on the Docker daemon around a run: closed-network support,
and the containers of the run's images, refused when running before a run and swept at its end
with `docker rm -f -v`, so a container's anonymous volumes go with it."""

import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from evals.cve.closed_network import ClosedNetworkUnsupported, check_closed_network_support
from evals.cve.images import ComposeImageStore, ImageStore
from evals.eval_session import Refused

DOCKER_REQUIREMENT = "Docker Engine 28.0 or later is required"


def refuse_without_closed_networks(
    check: Callable[[], None] = check_closed_network_support,
) -> None:
    try:
        check()
    except ClosedNetworkUnsupported as error:
        raise Refused(
            "the Docker daemon cannot create a closed network",
            [str(error), DOCKER_REQUIREMENT],
        ) from error


def running_containers(tags: Sequence[str]) -> list[str]:
    """The names of the running containers of each image tag, a name `docker rm` accepts."""
    names: list[str] = []
    for tag in tags:
        listing = subprocess.run(
            ["docker", "ps", "--filter", f"ancestor={tag}", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=True,
        )
        names.extend(name for name in listing.stdout.split() if name not in names)
    return names


def remove_containers(names: Sequence[str]) -> None:
    # Unchecked: a container that exits between the listing and its removal fails `docker rm`,
    # and an error raised from the run's `finally` would replace the run result it guards.
    subprocess.run(["docker", "rm", "-f", "-v", *names], capture_output=True, check=False)


@dataclass(frozen=True)
class ContainerSweep:
    running_containers: Callable[[Sequence[str]], list[str]]
    remove_containers: Callable[[Sequence[str]], None]


DOCKER_SWEEP = ContainerSweep(running_containers, remove_containers)


@dataclass(frozen=True)
class RunDocker:
    """What a command checks, reads and sweeps on the Docker daemon around its run."""

    check_networks: Callable[[], None] = check_closed_network_support
    images: ImageStore = field(default_factory=ComposeImageStore)
    sweep: ContainerSweep = DOCKER_SWEEP


def refuse_running_containers(running: Sequence[str], refusal: str) -> None:
    """A container of the run's images is a leftover of an earlier run or a concurrent run's:
    the maintainer removes it by hand."""
    if running:
        raise Refused(
            refusal, [f"a container of the run's images is running: {name}" for name in running]
        )


def sweep_containers(tags: Sequence[str], sweep: ContainerSweep) -> None:
    """Some servers outlive the end of their audit, the SIGKILL of their `docker` CLI included."""
    # A failed listing is only warned of, as a failed removal is not checked: an error raised
    # from the run's `finally` would replace the run result it guards. The next run's container
    # check refuses while a leftover is running.
    try:
        running = sweep.running_containers(tags)
    except subprocess.CalledProcessError:
        print("could not list the containers of the run's images, none removed")
        return
    if running:
        sweep.remove_containers(running)
        print(f"removed {len(running)} containers of the run's images left running")
