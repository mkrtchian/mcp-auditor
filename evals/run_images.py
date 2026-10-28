"""The image rebuild both run orchestrators share, the compose services of the targets, and the
containers of the run's images: refused when running before a run, swept at its end."""

import subprocess
from collections.abc import Callable, Sequence

from evals.cve_images import COMPOSE_FILE
from evals.cve_targets import CVETarget
from evals.eval_session import Refused

_BUILD_TAIL_LINES = 40


def rebuild_images(services: Sequence[str]) -> None:
    if not services:
        return
    build = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "build", *services],
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        raise RuntimeError(
            f"docker compose build failed for {', '.join(services)}:\n"
            f"{_tail(build.stdout)}\n{_tail(build.stderr)}"
        )


def _tail(output: str) -> str:
    return "\n".join(output.splitlines()[-_BUILD_TAIL_LINES:])


def target_services(targets: Sequence[CVETarget]) -> list[str]:
    """The deduplicated compose services of every target: its images and its patched twin."""
    services: list[str] = []
    for target in targets:
        for service in (*target.images, target.patched_image):
            if service not in services:
                services.append(service)
    return services


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
    subprocess.run(["docker", "rm", "-f", *names], capture_output=True, check=False)


def refuse_running_containers(running: Sequence[str], refusal: str) -> None:
    """A container of the run's images is a leftover of an earlier run or a concurrent run's:
    the maintainer removes it by hand."""
    if running:
        raise Refused(
            refusal, [f"a container of the run's images is running: {name}" for name in running]
        )


def sweep_containers(
    tags: Sequence[str],
    list_running: Callable[[Sequence[str]], list[str]],
    remove: Callable[[Sequence[str]], None],
) -> None:
    """Some servers outlive the end of their audit, the SIGKILL of their `docker` CLI included."""
    running = list_running(tags)
    if running:
        remove(running)
        print(f"removed {len(running)} containers of the run's images left running")
