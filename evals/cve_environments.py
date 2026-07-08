"""Per-target CVE environment context managers.

Each builder seeds a throwaway environment (temp root mounted into the
container, sidecars, networks), yields the Docker `Launch` that stands the
vulnerable server up, and tears everything down on exit, even on failure.

Setup calls (`docker network create`, sidecar `run -d`, seeding) run with
`check=True` so a failure raises before the yield: the runner maps that to a
skipped run. Teardown calls (`docker network rm`, `docker stop`) are
best-effort: a cleanup error must never raise out of `__exit__` and turn a run
that already produced a report into a skip. Orphans left by a failed teardown
carry the `mcp-auditor-cve` label; sweep them with:

    docker rm -f $(docker ps -aq --filter label=mcp-auditor-cve)
"""

import logging
import secrets
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from evals.cve_seeding import init_git_repo_with_commit, make_dir_with_file, plant_symlink

logger = logging.getLogger(__name__)

_LABEL = "mcp-auditor-cve"
_FILESYSTEM_IMAGE = "mcp-auditor-cve-filesystem:local"
_GIT_IMAGE = "mcp-auditor-cve-git:local"
_FETCH_IMAGE = "mcp-auditor-cve-fetch:local"
_SENTINEL_IMAGE = "mcp-auditor-cve-sentinel:local"


@dataclass(frozen=True)
class Launch:
    command: str
    args: list[str]
    chain_budget: int = 0
    max_chain_steps: int = 3  # only consulted when chain_budget > 0


@contextmanager
def filesystem_env(sentinel: str) -> Iterator[Launch]:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        (root / "sandbox").mkdir(parents=True)
        flag = make_dir_with_file(root / "outside", "flag.txt", sentinel)
        plant_symlink(root / "sandbox" / "report", flag)
        yield _filesystem_launch(root)


@contextmanager
def prefix_collision_env(sentinel: str) -> Iterator[Launch]:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        (root / "sandbox").mkdir(parents=True)
        make_dir_with_file(root / "sandbox_secret", "flag.txt", sentinel)
        yield _filesystem_launch(root)


@contextmanager
def repository_bypass_env(sentinel: str) -> Iterator[Launch]:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        init_git_repo_with_commit(root / "repo", "initial commit")
        init_git_repo_with_commit(root / "other", sentinel)
        yield _git_launch(root)


@contextmanager
def git_init_traversal_env(sentinel: str) -> Iterator[Launch]:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        init_git_repo_with_commit(root / "repo", "initial commit")
        make_dir_with_file(root / "secret", "flag.txt", sentinel)
        yield _git_launch(root, chain_budget=3, max_chain_steps=5)


@contextmanager
def command_injection_env(image: str, sentinel: str) -> Iterator[Launch]:
    yield Launch(command="docker", args=["run", "-i", "--rm", "-e", f"FLAG={sentinel}", image])


@contextmanager
def ssrf_env(sentinel: str) -> Iterator[Launch]:
    with (
        _docker_network() as network,
        _sidecar(
            _SENTINEL_IMAGE,
            "-e",
            f"FLAG={sentinel}",
            "--network",
            network,
            "--network-alias",
            "sentinel",
        ),
    ):
        yield Launch(
            command="docker",
            args=["run", "-i", "--rm", "--network", network, _FETCH_IMAGE],
        )


def _filesystem_launch(root: Path) -> Launch:
    return Launch(
        command="docker",
        args=["run", "-i", "--rm", "-v", f"{root}:/work", _FILESYSTEM_IMAGE, "/work/sandbox"],
    )


def _git_launch(root: Path, chain_budget: int = 0, max_chain_steps: int = 3) -> Launch:
    return Launch(
        command="docker",
        args=["run", "-i", "--rm", "-v", f"{root}:/work", _GIT_IMAGE, "--repository", "/work/repo"],
        chain_budget=chain_budget,
        max_chain_steps=max_chain_steps,
    )


@contextmanager
def _docker_network() -> Iterator[str]:
    name = f"{_LABEL}-{secrets.token_hex(6)}"
    subprocess.run(["docker", "network", "create", "--label", _LABEL, name], check=True)
    try:
        yield name
    finally:
        _best_effort("docker", "network", "rm", name)


@contextmanager
def _sidecar(image: str, *run_args: str) -> Iterator[str]:
    name = f"{_LABEL}-{secrets.token_hex(6)}"
    subprocess.run(
        ["docker", "run", "-d", "--rm", "--label", _LABEL, "--name", name, *run_args, image],
        check=True,
    )
    try:
        yield name
    finally:
        _best_effort("docker", "stop", name)


def _best_effort(*command: str) -> None:
    try:
        result = subprocess.run(list(command), check=False, capture_output=True, text=True)
    except OSError as error:
        logger.warning("cleanup command failed: %s (%s)", " ".join(command), error)
        return
    if result.returncode != 0:
        logger.warning("cleanup command failed: %s (%s)", " ".join(command), result.stderr.strip())
