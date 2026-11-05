import secrets
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from evals.cve_environments import git_init_traversal_env
from evals.cve_layout import build_layout, owned_layout
from evals.cve_planting import RANDOM_NONCES, PlantingHost, SymbolicUser, planting_spec
from evals.cve_planting_base import (
    LABEL,
    SENTINEL_IMAGE,
    LayoutMount,
    confinement_args,
    no_network_args,
)
from evals.cve_planting_docker import DOCKER_PLANTING
from evals.cve_targets import image_tag
from tests.integration.support.test_cve_planting_given import (
    missing_prerequisite as missing_prerequisite,
)

LayoutBuilder = Callable[[Path], None]
GIT_SERVICE = "git"  # the read-write git launch's image, which carries git, unlike the sentinel


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
    layout built and handed over through the real adapter, mounted read-only at /srv."""
    with owned_layout(DOCKER_PLANTING, builder) as root:
        return {command: _run_in_layout(root, command) for command in commands}


@dataclass(frozen=True)
class GitLaunchRun:
    result: CommandResult
    root: Path  # the layout root the launch mounted, gone once the launch exits


def an_unprivileged_server_on_the_git_launch_runs(command: str) -> GitLaunchRun:
    """The command run by `sh` in the git image, on the git launch's own options under a host
    declaring a read-write layout."""
    host = PlantingHost(
        SymbolicUser.UNPRIVILEGED, "/", has_network=False, layout_mount=LayoutMount.READ_WRITE
    )
    spec = planting_spec((), host, RANDOM_NONCES)
    image = image_tag(GIT_SERVICE)
    with git_init_traversal_env(image, spec) as launch:
        options = launch.args[: launch.args.index(image)]
        argv = ["docker", *options, "--entrypoint", "sh", image, "-c", command]
        completed = subprocess.run(
            argv, check=False, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL
        )
        root = _layout_root(options)
    return GitLaunchRun(
        CommandResult(completed.returncode, completed.stdout + completed.stderr), root
    )


def _layout_root(options: Sequence[str]) -> Path:
    mounts = [options[index + 1] for index, option in enumerate(options) if option == "-v"]
    return Path(next(mount for mount in mounts if mount.split(":")[1] == "/srv").split(":")[0])


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
