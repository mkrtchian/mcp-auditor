"""The Docker preflight of the CVE benchmark: the daemon and the expected images, checked
before any mode so a missing prerequisite reads as a crash and not as a detection miss."""

import subprocess
from collections.abc import Sequence

from rich.console import Console

from evals.cve_planting import SENTINEL_IMAGE
from evals.cve_targets import CVE_TARGETS, CVETarget, image_tag


def vulnerable_images(targets: Sequence[CVETarget]) -> tuple[str, ...]:
    return tuple(image_tag(name) for name in dict.fromkeys(n for t in targets for n in t.images))


def expected_images(targets: Sequence[CVETarget]) -> tuple[str, ...]:
    # Both versions of every server, plus the sentinel image unconditionally: a kept
    # http_endpoint and its namespace holder need it on any target, so dropping the fetch
    # target must not drop the sentinel from the preflight.
    services = dict.fromkeys(
        [name for t in targets for name in t.images] + [t.patched_image for t in targets]
    )
    tags = dict.fromkeys([image_tag(name) for name in services] + [SENTINEL_IMAGE])
    return tuple(tags)


# What capture_probe_corpus needs (it lists tools on the vulnerable images only), and what the
# benchmark preflight checks (both versions and the sentinel, so a missing patched image is a
# clear preflight error, not a replay whose every credit reads unchecked).
VULNERABLE_IMAGES = vulnerable_images(CVE_TARGETS)
EXPECTED_IMAGES = expected_images(CVE_TARGETS)
_BUILD_HINT = "run `docker compose -f evals/docker/compose.yml build`"

console = Console()


def preflight_ok() -> bool:
    if not _docker_ready():
        console.print(f"[red]Docker daemon unreachable.[/red] Start Docker, then {_BUILD_HINT}.")
        return False
    missing = [image for image in EXPECTED_IMAGES if not image_exists(image)]
    if missing:
        console.print(f"[red]Missing images:[/red] {', '.join(missing)}. To build: {_BUILD_HINT}.")
        return False
    _warn_if_pids_limit_discarded()
    return True


def _warn_if_pids_limit_discarded() -> None:
    # Docker does not fail on a limit its host cannot enforce, it warns on
    # stderr and runs without it, and the launchers discard stderr.
    result = subprocess.run(
        ["docker", "info", "--format", "{{.PidsLimit}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip() == "false":
        console.print(
            "[yellow]This Docker host cannot enforce --pids-limit, targets run without it.[/yellow]"
        )


def _docker_ready() -> bool:
    return _docker_command_succeeds(["docker", "info"])


def image_exists(image: str) -> bool:
    return _docker_command_succeeds(["docker", "image", "inspect", image])


def _docker_command_succeeds(command: list[str]) -> bool:
    try:
        return subprocess.run(command, capture_output=True).returncode == 0
    except OSError:
        return False
