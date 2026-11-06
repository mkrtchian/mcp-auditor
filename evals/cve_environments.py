"""Per-target CVE environment context managers. The builders only holdout targets use live in
`holdout_environments`, which reuses this module's launch types and helpers.

Each builder materialises the frozen `/srv` deployment layout (ADR 031) under a temp root
mounted into the container, adds whatever target-specific vulnerable structure its flaw needs,
hands the tree over to the unprivileged account (`owned_layout`), enters the generic planting
layer for the per-launch nonces and the network and sidecars a
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
layer creates for it closed (internal, with an isolated gateway, so it reaches
neither the host nor the Internet), where a planted endpoint is reached (the flaw).
A public name its benign call needs is pinned inside that network and served by a
stand-in replaying a dated capture. A change to the profile is checked by
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

A layout left by a failed removal, or by a launch cancelled while it was being entered, stays
in the host's temp directory as an `mcp-auditor-layout-*` directory holding a tree the host
user cannot delete. Sweep it with the pinned busybox the removal runs (`LAYOUT_HELPER_IMAGE`),
then remove the emptied directories (the `docker run` is one command, wrapped here):

    docker run --rm --user 0:0 --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add FOWNER
      --security-opt no-new-privileges --network none -v "${TMPDIR:-/tmp}":/x
      busybox:latest@sha256:fd8d9aa63ba2f0982b5304e1ee8d3b90a210bc1ffb5314d980eb6962f1a9715d
      sh -c 'rm -rf /x/mcp-auditor-layout-*/srv'
    rmdir "${TMPDIR:-/tmp}"/mcp-auditor-layout-*
"""

import json
import os
from collections.abc import AsyncGenerator, Generator, Mapping
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import IO

from evals.cve_layout import (
    ANCHOR_PATHS,
    build_empty_layout,
    build_layout,
    layout_mount_args,
    owned_layout,
)
from evals.cve_places import LayoutAnchor
from evals.cve_planting import (
    DockerPlanting,
    PlantedArgs,
    PlantingDocker,
    PlantingSpec,
    confinement_args,
    planted,
)
from evals.cve_planting_base import SentinelIntent
from evals.cve_planting_docker import DOCKER_PLANTING
from mcp_auditor.adapters.docker import docker_client_env
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.domain.ports import MCPClientPort

TOOL_CALL_TIMEOUT = 30  # the client's own default, the replay passes a short one to stay fast


class LaunchShape(StrEnum):
    """Which tree a builder materialises under the mount, and the scope it runs with. NORMAL is
    the frozen layout the benchmark runs under; EMPTY_LAYOUT is the rule's reference arm for the
    break detector, a minimal valid empty node at each layout anchor by node type
    (holdout-rule.md:159); FALLBACK keeps the layout mounted but scopes a scope-carrying server to
    its documented default, the launch the rule gates on a break (ADR 031). FALLBACK and NORMAL
    share the full tree."""

    NORMAL = "normal"
    EMPTY_LAYOUT = "empty_layout"
    FALLBACK = "fallback"


def materialise(root: Path, spec: PlantingSpec, shape: LaunchShape) -> None:
    # EMPTY_LAYOUT builds the rule's reference arm (a minimal valid empty node at each anchor by
    # node type); NORMAL and FALLBACK both build the full neutral tree, since the fallback keeps the
    # layout mounted.
    # The FALLBACK launch applies only FALLBACK_SCOPE, not a target's FallbackScope shape: honouring
    # an arbitrary per-target fallback scope (EMPTY_OUTSIDE, a non-PROJECT path) is deferred below.
    if shape is LaunchShape.EMPTY_LAYOUT:
        build_empty_layout(root)
    else:
        build_layout(root, spec.layout)


_WORKSPACE = ANCHOR_PATHS[LayoutAnchor.WORKSPACE]  # the mount target, /srv
PROJECT = ANCHOR_PATHS[LayoutAnchor.PROJECT]  # the in-scope checkout, /srv/app
CHECKOUT = Path(PROJECT).relative_to(_WORKSPACE)  # the checkout's path under the temp root

# The documented default scope a scope-carrying server falls back to when the layout breaks it
# (holdout-rule.md, Deployment layout (A server the layout breaks)): the in-scope checkout the
# deployment documents as the server's scope (ADR 031). Unexercised today, every acceptance target
# keeps the normal launch-mode and no target breaks (the behaviour smoke-check started all servers
# in the tree), so the fallback scope equals the normal scope here; a target the layout breaks would
# carry its own fallback scope on the card. The per-target CVETarget.fallback_scope is read only by
# fixture_fingerprint today, never by a builder. Wiring an arbitrary fallback scope (its three
# shapes) into the launch waits for the holdout-run machinery that does not exist yet, so a FALLBACK
# launch-mode with a scope other than this PROJECT default would not be honoured yet. It stays
# inert while every target keeps the normal launch-mode.
FALLBACK_SCOPE = PROJECT


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
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    with (
        owned_layout(docker, lambda root: _materialise_with_leak_links(root, spec, shape)) as root,
        planted(spec, image, docker) as args,
    ):
        yield filesystem_launch(layout_mount_args(root, spec.host.layout_mount), image, args)


def _materialise_with_leak_links(root: Path, spec: PlantingSpec, shape: LaunchShape) -> None:
    # One leak<N>/report symlink inside the in-scope checkout per planted file place, pointing
    # (absolute) at the coordinate where the nonce is mounted. The flaw follows it out of scope;
    # the patched server does not. The exploit discovers them by listing the checkout. The
    # prefix-collision sibling needs no extra structure: app.git is in the tree. The reference arm
    # (EMPTY_LAYOUT) plants nothing and has no checkout to hang a symlink off; the fallback keeps
    # the full tree, so it plants them like the normal launch. Built before the hand-over, so the
    # links are the account's too.
    materialise(root, spec, shape)
    if shape is not LaunchShape.EMPTY_LAYOUT:
        checkout = root / CHECKOUT
        for index, intent in enumerate(spec.files):
            leak = checkout / f"leak{index}"
            leak.mkdir()
            os.symlink(intent.container_path, leak / "report")


@contextmanager
def git_init_traversal_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    with (
        owned_layout(docker, lambda root: materialise(root, spec, shape)) as root,
        planted(spec, image, docker) as args,
    ):
        layout = layout_mount_args(root, spec.host.layout_mount)
        yield _git_launch(layout, image, args, chain_budget=3, max_chain_steps=5)


@contextmanager
def command_injection_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    with (
        owned_layout(docker, lambda root: materialise(root, spec, shape)) as root,
        planted(spec, image, docker) as args,
    ):
        yield Launch(
            command="docker",
            args=[
                "run",
                "-i",
                "--rm",
                *confinement_args(),
                *args.run_args(),
                *layout_mount_args(root, spec.host.layout_mount),
                image,
            ],
        )


@contextmanager
def ssrf_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    with (
        owned_layout(docker, lambda root: materialise(root, spec, shape)) as root,
        planted(spec, image, docker) as args,
    ):
        yield Launch(
            command="docker",
            args=[
                "run",
                "-i",
                "--rm",
                *confinement_args(),
                *args.run_args(),
                *layout_mount_args(root, spec.host.layout_mount),
                image,
            ],
        )


# The rebinding hosts resolve here at REST-tool creation (passing the gateway's creation-time SSRF
# check), then the entrypoint flips /etc/hosts to the internal sentinels at invocation.
_GW_PUBLIC_IP = "8.8.8.8"


@contextmanager
def contextforge_ssrf_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    # The real ContextForge gateway runs as root inside the sentinels' namespace holder (joined via
    # args.network) so its entrypoint can rewrite /etc/hosts for the DNS rebinding: a rebinding host
    # resolves public at REST-tool creation and internal at invocation (the TOCTOU the flaw turns
    # on). No /srv layout is mounted (the flaw is a network fetch, not a filesystem read), so the
    # shape is inert; the reference arm plants no sentinel, so GW_TOOLS is empty and the gateway
    # registers no tool.
    with planted(spec, image, DockerPlanting()) as args:
        yield Launch(
            command="docker",
            args=[
                "run",
                "-i",
                "--rm",
                *confinement_args(),
                "--user",
                "0:0",  # root: the entrypoint rewrites /etc/hosts to perform the DNS rebinding
                "-e",
                f"GW_PUBLIC_IP={_GW_PUBLIC_IP}",
                "-e",
                "GW_TOOLS=" + json.dumps(_gw_tools(spec)),
                *args.env,
                *args.network,
                image,
            ],
        )


def _gw_tools(spec: PlantingSpec) -> list[dict[str, str | None]]:
    # One REST tool per planted http_endpoint place: the rebinding hostname the gateway validates
    # at creation, the internal bind address it flips to, and the sentinel's request path.
    by_host: dict[tuple[str | None, str | None], SentinelIntent] = {
        (s.host, s.path): s for s in spec.sentinels
    }
    tools: list[dict[str, str | None]] = []
    for index, place in enumerate(spec.places):
        coordinates = place.coordinates
        sentinel = by_host.get((coordinates.host, coordinates.path))
        if sentinel is None:
            continue
        tools.append(
            {
                "place": place.id,
                "rebind": f"rb{index}.cve",
                "ip": sentinel.bind_address,
                "path": sentinel.request_target,
            }
        )
    return tools


def filesystem_launch(layout: list[str], image: str, args: PlantedArgs) -> Launch:
    return Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *confinement_args(),
            *args.run_args(),
            *layout,
            image,
            PROJECT,
        ],
        scope=PROJECT,
    )


def _git_launch(
    layout: list[str],
    image: str,
    args: PlantedArgs,
    chain_budget: int = 0,
    max_chain_steps: int = 3,
) -> Launch:
    return Launch(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            *confinement_args(),
            *args.run_args(),
            *layout,
            image,
            "--repository",
            PROJECT,
        ],
        chain_budget=chain_budget,
        max_chain_steps=max_chain_steps,
        scope=PROJECT,
    )
