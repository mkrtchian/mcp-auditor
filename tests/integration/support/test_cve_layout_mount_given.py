import secrets
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from evals.cve_layout import build_layout
from evals.cve_planting_base import LABEL, SENTINEL_IMAGE, confinement_args, no_network_args
from tests.integration.support.test_cve_planting_given import (
    missing_prerequisite as missing_prerequisite,
)

LayoutBuilder = Callable[[Path], None]


def the_full_layout(root: Path) -> None:
    build_layout(root, [])


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    output: str


def an_unprivileged_server_reads(
    builder: LayoutBuilder, commands: Sequence[str]
) -> dict[str, CommandResult]:
    """Each command run from the checkout, as a server under the unprivileged account, with the
    layout built in a fresh temp root (0700, as the launches make it) mounted read-only at /srv."""
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        builder(root)
        return {command: _run_in_layout(root, command) for command in commands}


def _run_in_layout(root: Path, command: str) -> CommandResult:
    argv = [
        "docker", "run", "--rm", "--label", LABEL,
        "--name", f"{LABEL}-layout-test-{secrets.token_hex(6)}",
        *confinement_args(), *no_network_args(), "--user", "65534:65534",
        "-v", f"{root}:/srv:ro", "-w", "/srv/app",
        "--entrypoint", "sh", SENTINEL_IMAGE, "-c", command,
    ]  # fmt: skip
    completed = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=60)
    return CommandResult(completed.returncode, completed.stdout + completed.stderr)
