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

import json
import os
import subprocess
import tempfile
import time
from collections.abc import AsyncGenerator, Generator, Mapping
from contextlib import asynccontextmanager, contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import IO
from uuid import uuid4

from evals.cve_layout import ANCHOR_PATHS, build_empty_layout, build_layout
from evals.cve_places import LayoutAnchor
from evals.cve_planting import (
    DockerPlanting,
    PlantedArgs,
    PlantingSpec,
    confinement_args,
    planted,
)
from evals.cve_planting_base import LABEL, SENTINEL_IMAGE, SentinelIntent
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


def _materialise(root: Path, spec: PlantingSpec, shape: LaunchShape) -> None:
    # EMPTY_LAYOUT builds the rule's reference arm (a minimal valid empty node at each anchor by
    # node type); NORMAL and FALLBACK both build the full neutral tree, since the fallback keeps the
    # layout mounted.
    # The FALLBACK launch applies only FALLBACK_SCOPE, not a target's FallbackScope shape: honouring
    # an arbitrary per-target fallback scope (EMPTY_OUTSIDE, a non-_PROJECT path) is deferred below.
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
# The per-target CVETarget.fallback_scope is read only by fixture_fingerprint today, never by a
# builder. Wiring an arbitrary fallback scope (its three shapes) into the launch waits for the
# holdout-run machinery that does not exist yet, so a FALLBACK launch-mode with a scope other than
# this _PROJECT default would not be honoured yet. It stays inert while every target keeps the
# normal launch-mode.
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
def arcadedb_mcp_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    # The ArcadeDB MCP stdio server reads files and fetches endpoints through the same polyglot-JS
    # sandbox escape, so its kept places span planted files, the hostname, the process environment
    # and the holder-bound metadata sentinels. It takes no scope argument (it is driven over stdio,
    # not pointed at a directory), so the launch is the read-only /srv mount and the planting
    # layer's args, with no path appended after the image.
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


_N8N_REDIRECT_IMAGE = "mcp-auditor-cve-holdout-ghsa-8g7g-hmwm-6rv2-n8n-redirect:local"
_N8N_STUB_IP = "203.0.113.10"  # TEST-NET-3: the SSRF guard treats it as an ordinary public host


@contextmanager
def ssrf_redirect_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    # ssrf_env plus a redirecting stand-in co-located in the sentinels' namespace holder. The
    # shared sentinels serve the per-launch nonce; the stand-in serves the workflow API and the 302
    # the server follows inward without re-validating (the flaw). planting() binds the IP-literal
    # sentinels inside a holder on loopback and the server joins that holder's namespace, so the
    # stand-in joins it too and binds a public-looking address the SSRF guard passes. The reference
    # arm plants no sentinel, so it joins no holder and needs no stand-in: launch the server plainly
    # then, exactly as ssrf_env's reference arm runs without its sentinel sidecar.
    with _temp_root() as root, planted(spec, image, DockerPlanting()) as args:
        _materialise(root, spec, shape)
        holder_ref = args.network[1] if _joins_holder(args.network) else None
        stub = _start_n8n_stub(holder_ref) if holder_ref is not None else None
        try:
            yield Launch(
                command="docker",
                args=[
                    "run",
                    "-i",
                    "--rm",
                    *confinement_args(),
                    *args.run_args(),
                    "-e",
                    f"N8N_API_URL=http://{_N8N_STUB_IP}/",
                    "-e",
                    "N8N_API_KEY=calib-key",
                    "-e",
                    "N8N_MCP_TELEMETRY_DISABLED=true",
                    "-v",
                    f"{root}:{_WORKSPACE}:ro",
                    image,
                ],
            )
        finally:
            if stub is not None:
                subprocess.run(["docker", "rm", "-f", stub], capture_output=True)


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


@contextmanager
def mysql_db_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    # The self-contained MySQL-MCP image carries its own engine and an AWS credential stub, both
    # started by the entrypoint, so the launch adds nothing but the frozen /srv layout, mounted
    # read-only (ADR 031). The server takes no scope argument, so none is appended after the image;
    # the network isolation, the planted file mounts, the planted env and the hostname all come
    # from the planting layer's PlantedArgs.
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


_DORIS_IMAGE = "apache/doris:all-in-one-4.1.3"
_MYSQL_CLIENT_IMAGE = "mysql:8.0"  # a throwaway MySQL-protocol client for the FE on port 9030
_DORIS_CONTAINER = "mcp-auditor-cve-doris"
_DORIS_BRIDGE = "mcp-auditor-cve-doris-bridge"  # server <-> Doris FE, name resolution
_DORIS_LLNET = "mcp-auditor-cve-doris-llnet"  # Doris <-> sentinels, static link-local IPs
_DORIS_LLSUBNET = "169.254.0.0/16"
DORIS_DB = "test_db"  # the database the server validates at connect, read by the exploit/benign
_DORIS_HEALTH_DEADLINE = 240.0
_DORIS_BACKEND_DEADLINE = 180.0


@contextmanager
def doris_db_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    # The flaw's internal fetch runs on the Doris backend (its http() TVF), not on the server
    # container, so the sentinels sit on a static-IP link-local bridge the Doris node reaches,
    # not behind the generic planting holder. The cluster is heavy (an FE+BE JVM) and persistent:
    # provisioned once and reused across exercises, only the per-launch sentinels are stood and
    # torn down here. No /srv layout is mounted: every kept place is an http_endpoint, so the
    # reference-arm shape has nothing to materialise and the server takes none.
    _ensure_doris()
    # doris-mcp-server does not exit on stdin EOF, so --rm cannot fire when the stdio adapter
    # reaps it and the container orphans; a unique name force-removed on teardown reaps it for
    # certain, so launches do not accumulate across calibration re-runs.
    server = f"{LABEL}-doris-server-{uuid4().hex}"
    sentinels: list[str] = []
    try:
        for sentinel in spec.sentinels:
            sentinels.append(_start_doris_sentinel(sentinel))
        time.sleep(2)  # let each sentinel's httpd bind before the server can drive a fetch
        yield Launch(
            command="docker",
            args=[
                "run",
                "-i",
                "--rm",
                *confinement_args(),
                "--name",
                server,
                "--label",
                LABEL,
                "--network",
                _DORIS_BRIDGE,
                image,
                "--db-host",
                _DORIS_CONTAINER,
                "--db-port",
                "9030",
                "--db-user",
                "root",
                "--db-database",
                DORIS_DB,
            ],
        )
    finally:
        _doris_rm(server)
        for name in sentinels:
            _doris_rm(name)


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


def _joins_holder(network: tuple[str, ...]) -> bool:
    return len(network) >= 2 and network[0] == "--network" and network[1].startswith("container:")


def _start_n8n_stub(holder_ref: str) -> str:
    # Bind the stand-in on a public-looking address inside the holder, then start it there: the
    # server joins the same namespace and reaches it on loopback, the SSRF guard passes the
    # TEST-NET-3 origin, and the 302 it serves points at the internal sentinel.
    subprocess.run(
        ["docker", "run", "--rm", "--label", LABEL, *confinement_args(),
         "--cap-add", "NET_ADMIN", "--network", holder_ref, "--entrypoint", "ip",
         SENTINEL_IMAGE, "addr", "add", f"{_N8N_STUB_IP}/32", "dev", "lo"],
        check=True, capture_output=True, text=True,
    )  # fmt: skip
    stub = f"{LABEL}-n8n-stub-{uuid4().hex}"
    subprocess.run(
        ["docker", "run", "-d", "--rm", "--label", LABEL, "--name", stub, *confinement_args(),
         "--cap-add", "NET_BIND_SERVICE", "--network", holder_ref,
         "-e", f"BIND_ADDR={_N8N_STUB_IP}", _N8N_REDIRECT_IMAGE],
        check=True, capture_output=True, text=True,
    )  # fmt: skip
    return stub


def _ensure_doris() -> None:
    _doris_network(_DORIS_BRIDGE)
    _doris_network(_DORIS_LLNET, _DORIS_LLSUBNET)
    if not _doris_running():
        if _doris_exists():
            _doris_rm(_DORIS_CONTAINER)
        _doris_run(
            "docker", "run", "-d",
            "--name", _DORIS_CONTAINER,
            "--hostname", _DORIS_CONTAINER,
            "--label", LABEL,
            "--network", _DORIS_BRIDGE,
            _DORIS_IMAGE,
        )  # fmt: skip
    _doris_run("docker", "network", "connect", _DORIS_LLNET, _DORIS_CONTAINER, check=False)
    _wait_doris_healthy()
    _provision_doris_schema()


def _wait_doris_healthy() -> None:
    deadline = time.monotonic() + _DORIS_HEALTH_DEADLINE
    while time.monotonic() < deadline:
        status = _doris_run(
            "docker", "inspect", "-f", "{{.State.Health.Status}}", _DORIS_CONTAINER, check=False
        )
        if status.stdout.strip() == "healthy":
            return
        time.sleep(5)
    raise RuntimeError("Doris front-end did not become healthy")


def _provision_doris_schema() -> None:
    # A bucketed table and a read of it both need a live backend, so retrying until both succeed
    # gates the yield on backend readiness: the exploit's fetch runs on the backend, and a backend
    # not yet up would otherwise read as a dead condition rather than a slow start.
    deadline = time.monotonic() + _DORIS_BACKEND_DEADLINE
    while time.monotonic() < deadline:
        _doris_sql(f"CREATE DATABASE IF NOT EXISTS {DORIS_DB};")
        created = _doris_sql(
            f"CREATE TABLE IF NOT EXISTS {DORIS_DB}.t1 (id INT) "
            "DISTRIBUTED BY HASH(id) BUCKETS 1 PROPERTIES('replication_num'='1');"
        )
        readable = _doris_sql(f"SELECT COUNT(*) FROM {DORIS_DB}.t1;")
        if created.returncode == 0 and readable.returncode == 0:
            return
        time.sleep(3)
    raise RuntimeError("Doris backend did not become query-ready")


def _start_doris_sentinel(sentinel: SentinelIntent) -> str:
    name = f"{LABEL}-doris-sentinel-{sentinel.host.replace('.', '-')}"
    _doris_rm(name)
    _doris_run(
        "docker", "run", "-d",
        "--name", name,
        "--label", LABEL,
        *confinement_args(),
        "--network", _DORIS_LLNET,
        "--ip", sentinel.host,
        "--cap-add", "NET_BIND_SERVICE",
        "-e", f"FLAG={sentinel.content}",
        "-e", f"SERVE_FILE={sentinel.served_file}",
        SENTINEL_IMAGE,
    )  # fmt: skip
    return name


def _doris_running() -> bool:
    return _DORIS_CONTAINER in _doris_names("docker", "ps")


def _doris_exists() -> bool:
    return _DORIS_CONTAINER in _doris_names("docker", "ps", "-a")


def _doris_names(*ps_command: str) -> list[str]:
    result = _doris_run(
        *ps_command, "--filter", f"name=^{_DORIS_CONTAINER}$", "--format", "{{.Names}}", check=False
    )
    return result.stdout.split()


def _doris_network(name: str, subnet: str | None = None) -> None:
    listed = _doris_run("docker", "network", "ls", "--format", "{{.Name}}", check=False)
    if name in listed.stdout.split():
        return
    args = ["docker", "network", "create", "--label", LABEL, name]
    if subnet is not None:
        args += ["--subnet", subnet]
    _doris_run(*args)


def _doris_sql(sql: str) -> subprocess.CompletedProcess[str]:
    return _doris_run(
        "docker", "run", "--rm", "--network", _DORIS_BRIDGE, _MYSQL_CLIENT_IMAGE,
        "mysql", f"-h{_DORIS_CONTAINER}", "-P9030", "-uroot", "--batch", "-e", sql,
        check=False, timeout=60,
    )  # fmt: skip


def _doris_run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


def _doris_rm(name: str) -> None:
    with suppress(subprocess.SubprocessError, OSError):
        _doris_run("docker", "rm", "-f", name, check=False)
