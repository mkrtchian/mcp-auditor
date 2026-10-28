"""The image rebuild both run orchestrators share, and the compose services of the targets."""

import subprocess
from collections.abc import Sequence

from evals.cve_images import COMPOSE_FILE
from evals.cve_targets import CVETarget

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
