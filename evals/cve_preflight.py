"""The Docker preflight of the CVE benchmark: the daemon and the expected images, checked
before any mode so a missing prerequisite reads as a crash and not as a detection miss. An
image whose Dockerfile fingerprint label does not match is rebuilt, so the benchmark never
audits whatever a tag happens to hold."""

import subprocess
from collections.abc import Sequence

from rich.console import Console

from evals.cve_images import ComposeImageStore, ImageBuildFailed, ImageStore, ensure_images
from evals.cve_planting import SENTINEL_SERVICE
from evals.cve_targets import CVE_TARGETS, CVETarget


def vulnerable_services(targets: Sequence[CVETarget]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(name for t in targets for name in t.images))


def expected_services(targets: Sequence[CVETarget]) -> tuple[str, ...]:
    # Both versions of every server, plus the sentinel unconditionally: a kept http_endpoint
    # and its namespace holder need it on any target, so dropping the fetch target must not
    # drop the sentinel from the preflight.
    return tuple(
        dict.fromkeys(
            [name for t in targets for name in t.images]
            + [t.patched_image for t in targets]
            + [SENTINEL_SERVICE]
        )
    )


# What capture_probe_corpus needs: it lists tools on the vulnerable images only.
VULNERABLE_SERVICES = vulnerable_services(CVE_TARGETS)

console = Console()


def preflight_ok(store: ImageStore | None = None) -> bool:
    if not _docker_ready():
        console.print("[red]Docker daemon unreachable.[/red] Start Docker, then run again.")
        return False
    try:
        rebuilt = ensure_images(expected_services(CVE_TARGETS), store or ComposeImageStore())
    except ImageBuildFailed as error:
        console.print(f"[red]Image build failed:[/red] {', '.join(error.services)}")
        console.print(error.stderr_tail, markup=False, highlight=False)
        return False
    if rebuilt:
        console.print(f"[yellow]Rebuilt stale images:[/yellow] {', '.join(rebuilt)}")
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
    try:
        return subprocess.run(["docker", "info"], capture_output=True).returncode == 0
    except OSError:
        return False
