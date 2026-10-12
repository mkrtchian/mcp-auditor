"""Per-target CVE environment context managers.

Each builder seeds a throwaway environment (a temp root mounted into the
container, the two git repos), enters the generic planting layer for the
per-launch nonces and the network and sidecars a kept place needs, yields the
Docker `Launch` that stands the vulnerable server up, and tears everything down
on exit, even on failure.

Every container the benchmark starts runs under `confinement_args`, and the
vulnerable servers whose image has no `USER` run as an unprivileged user. The
images are deliberately exploitable servers, and the auditor's own payloads reach
them, so the container is the only thing between an exploit that succeeds and
the host that runs the benchmark. The three servers that need no network run
with none: their images are built with everything they need, the auditor talks
to them over stdio, and the only use left for egress is an exploit that
succeeded and wants out. The SSRF target declares a network, which the planting
layer creates for it, a plain labelled bridge with the host gateway and Internet
egress, where a planted endpoint is reached (the flaw). A change to the profile is checked by
re-running `--calibrate`, which replays each fixture's exploit path under it
(the CI variant skips one CI-unstable target, so the full check is local). The
one-shot address-setup container a planted endpoint needs adds `NET_ADMIN` to
the profile and exits before the target starts, so no long-lived container holds
it, and a server without network may join a namespace holder on `--network none`,
which gives it the planted endpoint and still no egress.

The profile carries no memory bound yet. A server killed on memory mid-audit
would be counted as a missed detection and not as a skipped run, because the
client turns a closed connection into an error response and nothing reads the
container's kill state. The bound waits for that reader.

Seeding and the planting layer's setup (`docker network create`, a sidecar
`run -d`) raise before the yield on any failure: the runner maps that to a
skipped run. Teardown is best-effort: a cleanup error must never raise out of
`__exit__` and turn a run that already produced a report into a skip. The
benchmark enters and leaves these environments in a worker thread
(`entered_in_thread`): a namespace holder runs a `sleep` that ignores SIGTERM,
so planting removes it with `docker rm -f` rather than wait out a grace period
that would freeze every other audit on the event loop.
Orphans left by a failed teardown, or by a launch cancelled while it was being
entered in a worker thread (Ctrl-C, or a crash that ends the event loop, with no
`__exit__` to undo it), carry the `mcp-auditor-cve` label: a namespace holder, a
sentinel, an auto-allocated network. Sweep the containers first, then the
networks, since a network with a container attached cannot be removed:

    docker rm -f $(docker ps -aq --filter label=mcp-auditor-cve)
    docker network rm $(docker network ls -q --filter label=mcp-auditor-cve)
"""

import os
import tempfile
from collections.abc import AsyncGenerator, Generator, Mapping
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from evals.cve_planting import (
    DockerPlanting,
    PlantedArgs,
    PlantingSpec,
    confinement_args,
    planted,
)
from evals.cve_seeding import init_git_repo_with_commit, make_dir_with_file, plant_symlink
from mcp_auditor.adapters.docker import docker_client_env
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.domain.ports import MCPClientPort

TOOL_CALL_TIMEOUT = 30  # the client's own default, the replay passes a short one to stay fast

# No per-launch nonce is written by hand any more: the proof is planted at a kept place
# through `planted`. The builders keep their vulnerable structure (the symlink, the sibling
# directory, the two repos) and seed it with this neutral marker, which the deferred fixture
# shaping repoints at a planted file.
_UNPLANTED = "unplanted"


@dataclass(frozen=True)
class Launch:
    command: str
    args: list[str]
    chain_budget: int = 0
    max_chain_steps: int = 3  # only consulted when chain_budget > 0


@dataclass(frozen=True)
class PlantedLaunch:
    launch: Launch
    nonces: Mapping[str, str]  # each planted location id to the value drawn for this launch


@asynccontextmanager
async def connect(
    launch: Launch, server_stderr: IO[str], *, tool_call_timeout: int = TOOL_CALL_TIMEOUT
) -> AsyncGenerator[MCPClientPort]:
    async with StdioMCPClient.connect(
        ServerLaunch.declared_container(launch.command, launch.args, docker_client_env(os.environ)),
        errlog=server_stderr,
        tool_call_timeout=tool_call_timeout,
    ) as client:
        yield client


@contextmanager
def filesystem_env(image: str, spec: PlantingSpec) -> Generator[Launch]:
    with _temp_root() as root, planted(spec, image, DockerPlanting()) as args:
        (root / "sandbox").mkdir(parents=True)
        flag = make_dir_with_file(root / "outside", "flag.txt", _UNPLANTED)
        plant_symlink(root / "sandbox" / "report", flag)
        yield _filesystem_launch(root, image, args)


@contextmanager
def prefix_collision_env(image: str, spec: PlantingSpec) -> Generator[Launch]:
    with _temp_root() as root, planted(spec, image, DockerPlanting()) as args:
        (root / "sandbox").mkdir(parents=True)
        make_dir_with_file(root / "sandbox_secret", "flag.txt", _UNPLANTED)
        yield _filesystem_launch(root, image, args)


@contextmanager
def repository_bypass_env(image: str, spec: PlantingSpec) -> Generator[Launch]:
    with _temp_root() as root, planted(spec, image, DockerPlanting()) as args:
        init_git_repo_with_commit(root / "repo", "initial commit")
        init_git_repo_with_commit(root / "other", _UNPLANTED)
        yield _git_launch(root, image, args)


@contextmanager
def git_init_traversal_env(image: str, spec: PlantingSpec) -> Generator[Launch]:
    with _temp_root() as root, planted(spec, image, DockerPlanting()) as args:
        init_git_repo_with_commit(root / "repo", "initial commit")
        make_dir_with_file(root / "secret", "flag.txt", _UNPLANTED)
        yield _git_launch(root, image, args, chain_budget=3, max_chain_steps=5)


@contextmanager
def command_injection_env(image: str, spec: PlantingSpec) -> Generator[Launch]:
    with planted(spec, image, DockerPlanting()) as args:
        yield Launch(
            command="docker",
            args=["run", "-i", "--rm", *confinement_args(), *args.run_args(), image],
        )


@contextmanager
def ssrf_env(image: str, spec: PlantingSpec) -> Generator[Launch]:
    with planted(spec, image, DockerPlanting()) as args:
        yield Launch(
            command="docker",
            args=["run", "-i", "--rm", *confinement_args(), *args.run_args(), image],
        )


@contextmanager
def _temp_root() -> Generator[Path]:
    # The filesystem and git launches run as the host user, so bind-mount files are host-owned
    # and rmtree normally succeeds. ignore_cleanup_errors stays as a fallback so a stray
    # un-removable file never crashes a run at __exit__.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as name:
        yield Path(name)


def _filesystem_launch(root: Path, image: str, args: PlantedArgs) -> Launch:
    return Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *confinement_args(),
            *args.run_args(),
            "-v",
            f"{root}:/work",
            image,
            "/work/sandbox",
        ],
    )


def _git_launch(
    root: Path, image: str, args: PlantedArgs, chain_budget: int = 0, max_chain_steps: int = 3
) -> Launch:
    return Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *confinement_args(),
            *args.run_args(),
            "-v",
            f"{root}:/work",
            image,
            "--repository",
            "/work/repo",
        ],
        chain_budget=chain_budget,
        max_chain_steps=max_chain_steps,
    )
