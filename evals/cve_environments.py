"""Per-target CVE environment context managers.

Each builder materialises the frozen `/srv` deployment layout (ADR 031) under a temp root
mounted into the container, adds whatever target-specific vulnerable structure its flaw needs,
enters the generic planting layer for the per-launch nonces and the network and sidecars a
kept place needs, yields the Docker `Launch` that stands the vulnerable server up, and tears
everything down on exit, even on failure.

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

Building the layout tree and the planting layer's setup (`docker network
create`, a sidecar `run -d`) raise before the yield on any failure: the runner
maps that to a skipped run. Teardown is best-effort: a cleanup error must never raise out of
`__exit__` and turn a run that already produced a report into a skip. The
benchmark enters and leaves these environments in a worker thread
(`entered_in_thread`). A namespace holder runs a `sleep` and a sentinel's
`httpd` runs as PID 1, both ignoring SIGTERM, so planting removes holder and
sentinels alike with `docker rm -f` rather than wait out a pointless grace
period per container: teardown runs in the worker thread, so the wait would not
freeze the event loop, it would only waste the grace.
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
from enum import StrEnum
from pathlib import Path
from typing import IO

from evals.cve_layout import ANCHOR_PATHS, build_empty_layout, build_layout
from evals.cve_places import LayoutAnchor
from evals.cve_planting import (
    DockerPlanting,
    PlantedArgs,
    PlantingSpec,
    confinement_args,
    planted,
)
from mcp_auditor.adapters.docker import docker_client_env
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.domain.ports import MCPClientPort

TOOL_CALL_TIMEOUT = 30  # the client's own default, the replay passes a short one to stay fast


class LaunchShape(StrEnum):
    """Which tree a builder materialises under the mount, and the scope it runs with. NORMAL is
    the frozen layout the benchmark runs under; EMPTY_LAYOUT is the rule's reference arm for the
    break detector, an empty directory at each layout anchor (holdout-rule.md:159); FALLBACK keeps
    the layout mounted but scopes a scope-carrying server to its documented default, the launch the
    rule gates on a break (ADR 031). FALLBACK and NORMAL share the full tree."""

    NORMAL = "normal"
    EMPTY_LAYOUT = "empty_layout"
    FALLBACK = "fallback"


def _materialise(root: Path, spec: PlantingSpec, shape: LaunchShape) -> None:
    # EMPTY_LAYOUT builds the rule's reference arm (an empty directory at each anchor); NORMAL and
    # FALLBACK both build the full neutral tree, since the fallback keeps the layout mounted.
    if shape is LaunchShape.EMPTY_LAYOUT:
        build_empty_layout(root)
    else:
        build_layout(root, spec.layout)


_WORKSPACE = ANCHOR_PATHS[LayoutAnchor.WORKSPACE]  # the mount target, /srv
_PROJECT = ANCHOR_PATHS[LayoutAnchor.PROJECT]  # the in-scope checkout, /srv/app
_CHECKOUT = Path(_PROJECT).relative_to(_WORKSPACE)  # the checkout's path under the temp root

# The documented default scope a scope-carrying server falls back to when the layout breaks it
# (holdout-rule.md:159): the in-scope checkout the deployment documents as the server's scope
# (ADR 031). Unexercised today, every acceptance target keeps the normal launch-mode and no target
# breaks (the behaviour smoke-check started all servers in the tree), so the fallback scope equals
# the normal scope here; a target the layout breaks would carry its own fallback scope on the card.
FALLBACK_SCOPE = _PROJECT


@dataclass(frozen=True)
class Launch:
    command: str
    args: list[str]
    chain_budget: int = 0
    max_chain_steps: int = 3  # only consulted when chain_budget > 0
    scope: str | None = None  # the scope the layout dictates, the route check reads it here


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
def filesystem_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    with _temp_root() as root, planted(spec, image, DockerPlanting()) as args:
        _materialise(root, spec, shape)
        # One leak<N>/report symlink inside the in-scope checkout per planted file place,
        # pointing (absolute) at the coordinate where the nonce is mounted. The flaw follows it
        # out of scope; the patched server does not. The exploit discovers them by listing the
        # checkout. The prefix-collision sibling needs no extra structure: app.git is in the tree.
        # The reference arm (EMPTY_LAYOUT) plants nothing and has no checkout to hang a symlink off;
        # the fallback keeps the full tree, so it plants them like the normal launch.
        if shape is not LaunchShape.EMPTY_LAYOUT:
            checkout = root / _CHECKOUT
            for index, intent in enumerate(spec.files):
                leak = checkout / f"leak{index}"
                leak.mkdir()
                os.symlink(intent.container_path, leak / "report")
        yield _filesystem_launch(root, image, args)


@contextmanager
def git_init_traversal_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    with _temp_root() as root, planted(spec, image, DockerPlanting()) as args:
        _materialise(root, spec, shape)
        yield _git_launch(root, image, args, chain_budget=3, max_chain_steps=5)


@contextmanager
def command_injection_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    with _temp_root() as root, planted(spec, image, DockerPlanting()) as args:
        _materialise(root, spec, shape)
        yield Launch(
            command="docker",
            args=[
                "run",
                "-i",
                "--rm",
                *confinement_args(),
                *args.run_args(),
                "-v",
                f"{root}:{_WORKSPACE}:ro",
                image,
            ],
        )


@contextmanager
def ssrf_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    with _temp_root() as root, planted(spec, image, DockerPlanting()) as args:
        _materialise(root, spec, shape)
        yield Launch(
            command="docker",
            args=[
                "run",
                "-i",
                "--rm",
                *confinement_args(),
                *args.run_args(),
                "-v",
                f"{root}:{_WORKSPACE}:ro",
                image,
            ],
        )


@contextmanager
def _temp_root() -> Generator[Path]:
    # The filesystem and git launches run as the host user, so bind-mount files are host-owned
    # and rmtree normally succeeds. ignore_cleanup_errors stays as a fallback so a stray
    # un-removable file never crashes a run at __exit__.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as name:
        yield Path(name)


def _filesystem_launch(root: Path, image: str, args: PlantedArgs) -> Launch:
    # Read-only: the filesystem server only reads, and git_init (the one writer) belongs to the
    # git target, which mounts read-write.
    return Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *confinement_args(),
            *args.run_args(),
            "-v",
            f"{root}:{_WORKSPACE}:ro",
            image,
            _PROJECT,
        ],
        scope=_PROJECT,
    )


def _git_launch(
    root: Path, image: str, args: PlantedArgs, chain_budget: int = 0, max_chain_steps: int = 3
) -> Launch:
    # Read-write: git_init writes a .git into /srv, and git operates on a repo it owns.
    return Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *confinement_args(),
            *args.run_args(),
            "-v",
            f"{root}:{_WORKSPACE}",
            image,
            "--repository",
            _PROJECT,
        ],
        chain_budget=chain_budget,
        max_chain_steps=max_chain_steps,
        scope=_PROJECT,
    )
