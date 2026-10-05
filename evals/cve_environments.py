"""Per-target CVE environment context managers.

Each builder seeds a throwaway environment (temp root mounted into the
container, sidecars, networks), yields the Docker `Launch` that stands the
vulnerable server up, and tears everything down on exit, even on failure.

Every container the benchmark starts runs under `_confinement_args`, and the
vulnerable servers whose image has no `USER` run as an unprivileged user. The
images are deliberately exploitable servers, and the auditor's own payloads reach
them, so the container is the only thing between an exploit that succeeds and
the host that runs the benchmark. The three servers that need no network run
with none: their images are built with everything they need, the auditor talks
to them over stdio, and the only use left for egress is an exploit that
succeeded and wants out. The SSRF target keeps a dedicated network, because
reaching the sentinel over it is the flaw, and that network is a plain bridge
with the host gateway and Internet egress. A change to the profile is checked by
re-running `--calibrate`, which replays each fixture's exploit path under it
(the CI variant skips one CI-unstable target, so the full check is local).

The profile carries no memory bound yet. A server killed on memory mid-audit
would be counted as a missed detection and not as a skipped run, because the
client turns a closed connection into an error response and nothing reads the
container's kill state. The bound waits for that reader.

Setup calls (`docker network create`, sidecar `run -d`, seeding) run with
`check=True` so a failure raises before the yield: the runner maps that to a
skipped run. Teardown calls (`docker network rm`, `docker stop`) are
best-effort: a cleanup error must never raise out of `__exit__` and turn a run
that already produced a report into a skip. The benchmark enters and leaves
these environments in a worker thread (`entered_in_thread`): leaving the SSRF
environment stops a sidecar that ignores SIGTERM, so `docker stop` waits its
10 s grace period, which would freeze every other audit on the event loop.
Orphans left by a failed teardown carry the `mcp-auditor-cve` label; sweep them
with:

    docker rm -f $(docker ps -aq --filter label=mcp-auditor-cve)
"""

# This module is part of every CVE baseline's fixture fingerprint, which hashes annotations:
# renaming the Iterator return types pyright deprecates would reset the whole baseline.
# pyright: reportDeprecated=false

import logging
import os
import secrets
import subprocess
import tempfile
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from evals.cve_seeding import init_git_repo_with_commit, make_dir_with_file, plant_symlink
from mcp_auditor.adapters.docker import docker_client_env
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.domain.ports import MCPClientPort

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


@asynccontextmanager
async def connect(launch: Launch, server_stderr: IO[str]) -> AsyncIterator[MCPClientPort]:
    async with StdioMCPClient.connect(
        ServerLaunch.declared_container(launch.command, launch.args, docker_client_env(os.environ)),
        errlog=server_stderr,
    ) as client:
        yield client


@contextmanager
def filesystem_env(sentinel: str) -> Iterator[Launch]:
    with _temp_root() as root:
        (root / "sandbox").mkdir(parents=True)
        flag = make_dir_with_file(root / "outside", "flag.txt", sentinel)
        plant_symlink(root / "sandbox" / "report", flag)
        yield _filesystem_launch(root)


@contextmanager
def prefix_collision_env(sentinel: str) -> Iterator[Launch]:
    with _temp_root() as root:
        (root / "sandbox").mkdir(parents=True)
        make_dir_with_file(root / "sandbox_secret", "flag.txt", sentinel)
        yield _filesystem_launch(root)


@contextmanager
def repository_bypass_env(sentinel: str) -> Iterator[Launch]:
    with _temp_root() as root:
        init_git_repo_with_commit(root / "repo", "initial commit")
        init_git_repo_with_commit(root / "other", sentinel)
        yield _git_launch(root)


@contextmanager
def git_init_traversal_env(sentinel: str) -> Iterator[Launch]:
    with _temp_root() as root:
        init_git_repo_with_commit(root / "repo", "initial commit")
        make_dir_with_file(root / "secret", "flag.txt", sentinel)
        yield _git_launch(root, chain_budget=3, max_chain_steps=5)


@contextmanager
def command_injection_env(image: str, sentinel: str) -> Iterator[Launch]:
    yield Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *_confinement_args(),
            *_no_network_args(),
            *_unprivileged_user_args(),
            "-e",
            f"FLAG={sentinel}",
            image,
        ],
    )


@contextmanager
def ssrf_env(sentinel: str) -> Iterator[Launch]:
    with (
        _docker_network() as network,
        _sidecar(
            _SENTINEL_IMAGE,
            # The sentinel serves on :80. Without this the bind only works because
            # Docker lowers ip_unprivileged_port_start inside the container, a
            # default another runtime may not share.
            "--cap-add",
            "NET_BIND_SERVICE",
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
            args=[
                "run",
                "-i",
                "--rm",
                *_confinement_args(),
                *_unprivileged_user_args(),
                "--network",
                network,
                _FETCH_IMAGE,
            ],
        )


@contextmanager
def _temp_root() -> Iterator[Path]:
    # Containers run as the host user (see _host_user_args), so bind-mount files
    # are host-owned and rmtree normally succeeds. ignore_cleanup_errors stays as
    # a fallback so a stray un-removable file never crashes a run at __exit__.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as name:
        yield Path(name)


def _confinement_args() -> list[str]:
    # The process bound is about twenty times what these servers run at rest,
    # and it fails gracefully: fork returns EAGAIN and the server survives, so
    # the bound cannot turn a run into a false miss the way a memory kill would.
    return [
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
    ]


def _no_network_args() -> list[str]:
    return ["--network", "none"]


def _unprivileged_user_args() -> list[str]:
    # An image without a USER runs as root inside the container. Behind an empty
    # capability bounding set that root is disarmed, but an escape that lands as
    # nobody on the host is still better than one that lands as root.
    return ["--user", "65534:65534", "-e", "HOME=/tmp"]


def _host_user_args() -> list[str]:
    # Run the bind-mount containers as the host user so files the server writes
    # into /work (e.g. git_init's .git) are host-owned. The CVE is a scope/path
    # bug, independent of the container uid, so this preserves the exploit while
    # letting teardown remove the files and git operate on a repo it owns. HOME
    # is set because git needs a writable home for a uid absent from the image's
    # passwd file.
    return ["--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp"]


def _filesystem_launch(root: Path) -> Launch:
    return Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *_confinement_args(),
            *_no_network_args(),
            *_host_user_args(),
            "-v",
            f"{root}:/work",
            _FILESYSTEM_IMAGE,
            "/work/sandbox",
        ],
    )


def _git_launch(root: Path, chain_budget: int = 0, max_chain_steps: int = 3) -> Launch:
    return Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *_confinement_args(),
            *_no_network_args(),
            *_host_user_args(),
            "-v",
            f"{root}:/work",
            _GIT_IMAGE,
            "--repository",
            "/work/repo",
        ],
        chain_budget=chain_budget,
        max_chain_steps=max_chain_steps,
    )


@contextmanager
def _docker_network() -> Iterator[str]:
    name = f"{_LABEL}-{secrets.token_hex(6)}"
    subprocess.run(
        ["docker", "network", "create", "--label", _LABEL, name], check=True, capture_output=True
    )
    try:
        yield name
    finally:
        _best_effort("docker", "network", "rm", name)


@contextmanager
def _sidecar(image: str, *run_args: str) -> Iterator[str]:
    name = f"{_LABEL}-{secrets.token_hex(6)}"
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            *_confinement_args(),
            "--label",
            _LABEL,
            "--name",
            name,
            *run_args,
            image,
        ],
        check=True,
        capture_output=True,
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
