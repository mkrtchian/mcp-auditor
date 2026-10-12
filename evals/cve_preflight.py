"""The Docker preflight of the CVE benchmark: the daemon and the expected images, checked
before any mode so a missing prerequisite reads as a crash and not as a detection miss."""

import subprocess

from rich.console import Console

from evals.cve_targets import CVE_TARGETS, image_tag

EXPECTED_IMAGES = tuple(
    image_tag(name) for name in dict.fromkeys(n for t in CVE_TARGETS for n in t.images)
)
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
