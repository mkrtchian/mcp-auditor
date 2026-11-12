import secrets
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from evals.cve.detection.targets import image_tag
from evals.cve.environments import git_init_traversal_env
from evals.cve.layout import build_layout, owned_layout
from evals.cve.planting import RANDOM_NONCES, PlantingHost, SymbolicUser, planting_spec
from evals.cve.planting_base import (
    LABEL,
    SENTINEL_IMAGE,
    LayoutMount,
    confinement_args,
    no_network_args,
)
from evals.cve.planting_docker import DOCKER_PLANTING
from tests.integration.support.test_cve_planting_given import a_work_spec
from tests.integration.support.test_cve_planting_given import (
    missing_prerequisite as missing_prerequisite,
)
from tests.unit.support.docker_argv import mount_of

LayoutBuilder = Callable[[Path], None]
GIT_SERVICE = "git"  # the read-write git launch's image, which carries git, unlike the sentinel
UNPRIVILEGED_USER = "65534:65534"  # the layout's owner


def the_full_layout(root: Path) -> None:
    build_layout(root, [])


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    output: str


def an_unprivileged_server_reads(
    builder: LayoutBuilder, commands: Sequence[str], user: str = UNPRIVILEGED_USER
) -> dict[str, CommandResult]:
    """Each command run from the checkout as `user`, with the layout built and handed over through
    the real adapter, mounted read-only at /srv."""
    with owned_layout(DOCKER_PLANTING, builder) as root:
        return {command: _run_in_layout(root, command, user) for command in commands}


def the_planted_account() -> str:
    """The `uid:gid` a target with an account place runs under, which does not own the layout."""
    account = a_work_spec(with_an_account=True).account
    assert account is not None
    return f"{account.uid}:{account.gid}"


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
        root = Path(mount_of(options, "/srv").split(":")[0])
    return GitLaunchRun(
        CommandResult(completed.returncode, completed.stdout + completed.stderr), root
    )


def _run_in_layout(root: Path, command: str, user: str) -> CommandResult:
    argv = [
        "docker", "run", "--rm", "--label", LABEL,
        "--name", f"{LABEL}-layout-test-{secrets.token_hex(6)}",
        *confinement_args(), *no_network_args(), "--user", user,
        "-v", f"{root}:/srv:ro", "-w", "/srv/app",
        "--entrypoint", "sh", SENTINEL_IMAGE, "-c", command,
    ]  # fmt: skip
    completed = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=60)
    return CommandResult(completed.returncode, completed.stdout + completed.stderr)
