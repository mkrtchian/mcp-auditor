"""The Docker preflight of the detection suite: the daemon and the expected images, checked
before any mode so a missing prerequisite reads as a crash and not as a detection miss. An
image whose Dockerfile fingerprint label does not match is rebuilt, so the suite never audits
whatever a tag happens to hold.

`python -m evals.detection_preflight` prints the expected services, the compose services the
calibration check job builds in CI."""

import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from rich.console import Console

from evals.cve.closed_network import ClosedNetworkUnsupported, check_closed_network_support
from evals.cve.detection.targets import ACCEPTANCE_TARGETS, Target
from evals.cve.images import ComposeImageStore, ImageBuildFailed, ImageStore, ensure_images
from evals.cve.planting import SENTINEL_SERVICE
from evals.cve.planting_base import STAND_IN_SERVICE
from evals.cve.run_images import DOCKER_REQUIREMENT


def vulnerable_services(targets: Sequence[Target]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(name for t in targets for name in t.images))


def expected_services(targets: Sequence[Target]) -> tuple[str, ...]:
    # Both versions of every server, plus the sentinel unconditionally: a kept http_endpoint
    # and its namespace holder need it on any target, so dropping the fetch target must not
    # drop the sentinel from the preflight.
    stand_ins = (
        [STAND_IN_SERVICE] if any(t.planting_host.public_names.stand_ins for t in targets) else []
    )
    return tuple(
        dict.fromkeys(
            [name for t in targets for name in t.images]
            + [t.patched_image for t in targets]
            + [SENTINEL_SERVICE]
            + stand_ins
        )
    )


# What capture_probe_corpus needs: it lists tools on the vulnerable images only.
VULNERABLE_SERVICES = vulnerable_services(ACCEPTANCE_TARGETS)

console = Console()


@dataclass(frozen=True)
class PreflightDocker:
    ready: Callable[[], bool]
    enforces_pids_limit: Callable[[], bool]
    check_closed_networks: Callable[[], None]  # raises ClosedNetworkUnsupported
    images: ImageStore


def _docker_ready() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True).returncode == 0
    except OSError:
        return False


def _enforces_pids_limit() -> bool:
    # Docker does not fail on a limit its host cannot enforce, it warns on
    # stderr and runs without it, and the launchers discard stderr.
    result = subprocess.run(
        ["docker", "info", "--format", "{{.PidsLimit}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() != "false"


HOST_DOCKER = PreflightDocker(
    _docker_ready, _enforces_pids_limit, check_closed_network_support, ComposeImageStore()
)


def preflight_ok(docker: PreflightDocker = HOST_DOCKER) -> bool:
    if not docker.ready():
        console.print("[red]Docker daemon unreachable.[/red] Start Docker, then run again.")
        return False
    try:
        docker.check_closed_networks()
    except ClosedNetworkUnsupported as error:
        console.print("[red]The Docker daemon cannot create a closed network.[/red]")
        console.print(f"{error}\n{DOCKER_REQUIREMENT}", markup=False, highlight=False)
        return False
    try:
        rebuilt = ensure_images(expected_services(ACCEPTANCE_TARGETS), docker.images)
    except ImageBuildFailed as error:
        console.print(f"[red]Image build failed:[/red] {', '.join(error.services)}")
        console.print(error.stderr_tail, markup=False, highlight=False)
        return False
    if rebuilt:
        console.print(f"[yellow]Rebuilt stale images:[/yellow] {', '.join(rebuilt)}")
    if not docker.enforces_pids_limit():
        console.print(
            "[yellow]This Docker host cannot enforce --pids-limit, targets run without it.[/yellow]"
        )
    return True


def main() -> None:
    print(" ".join(expected_services(ACCEPTANCE_TARGETS)))


if __name__ == "__main__":
    main()
