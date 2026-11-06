"""The CVE environment builders only holdout targets use, beside the acceptance builders and the
shared launch types of `cve_environments`, whose module docstring (confinement, teardown, the
orphan sweep) governs these builders too. Fingerprinted into every CVE fixture with it
(`cve_baseline.ENVIRONMENT_PATHS`).
"""

import subprocess
import time
from collections.abc import Generator
from contextlib import contextmanager
from uuid import uuid4

from evals.cve_environments import Launch, LaunchShape, materialise
from evals.cve_layout import layout_mount_args, owned_layout
from evals.cve_planting import PlantingDocker, PlantingSpec, confinement_args, planted
from evals.cve_planting_base import LABEL, SENTINEL_IMAGE, own_network_args
from evals.cve_planting_docker import DOCKER_PLANTING
from evals.doris_backend import (
    DORIS_BRIDGE,
    DORIS_DB,
    DORIS_HOST,
    DORIS_LAUNCH_LOCK,
    doris_rm,
    ensure_doris,
    start_doris_sentinel,
)


@contextmanager
def arcadedb_mcp_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    # The ArcadeDB MCP stdio server reads files and fetches endpoints through the same polyglot-JS
    # sandbox escape, so its kept places span planted files, the hostname, the process environment
    # and the holder-bound metadata sentinels. It takes no scope argument (it is driven over stdio,
    # not pointed at a directory), so the launch is the /srv mount and the planting layer's args,
    # with no path appended after the image.
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


_N8N_REDIRECT_IMAGE = "mcp-auditor-cve-holdout-ghsa-8g7g-hmwm-6rv2-n8n-redirect:local"
_N8N_STUB_IP = "203.0.113.10"  # TEST-NET-3: the SSRF guard treats it as an ordinary public host


@contextmanager
def ssrf_redirect_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    # ssrf_env plus a redirecting stand-in co-located in the sentinels' namespace holder. The
    # shared sentinels serve the per-launch nonce; the stand-in serves the workflow API and the 302
    # the server follows inward without re-validating (the flaw). planting() binds the IP-literal
    # sentinels inside a holder on loopback and the server joins that holder's namespace, so the
    # stand-in joins it too and binds a public-looking address the SSRF guard passes. The reference
    # arm plants no sentinel, so it joins no holder and needs no stand-in: launch the server plainly
    # then, exactly as ssrf_env's reference arm runs without its sentinel sidecar.
    with (
        owned_layout(docker, lambda root: materialise(root, spec, shape)) as root,
        planted(spec, image, docker) as args,
    ):
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
                    *layout_mount_args(root, spec.host.layout_mount),
                    image,
                ],
            )
        finally:
            if stub is not None:
                subprocess.run(["docker", "rm", "-f", stub], capture_output=True)


@contextmanager
def mysql_db_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    # The self-contained MySQL-MCP image carries its own engine and an AWS credential stub, both
    # started by the entrypoint, so the launch adds nothing but the frozen /srv layout (ADR 031).
    # The server takes no scope argument, so none is appended after the image;
    # the network isolation, the planted file mounts, the planted env and the hostname all come
    # from the planting layer's PlantedArgs.
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
def doris_db_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    # The flaw's internal fetch runs on the Doris backend (its http() TVF), not on the server
    # container, so the sentinels sit on a static-IP link-local bridge the Doris node reaches,
    # not behind the generic planting holder. The cluster is heavy (an FE+BE JVM) and persistent:
    # provisioned once and reused across exercises, only the per-launch sentinels are stood and
    # torn down here. No /srv layout is mounted: every kept place is an http_endpoint, so the
    # reference-arm shape has nothing to materialise and the server takes none.
    with DORIS_LAUNCH_LOCK:
        ensure_doris()
        # doris-mcp-server does not exit on stdin EOF, so --rm cannot fire when the stdio adapter
        # reaps it and the container orphans; a unique name force-removed on teardown reaps it for
        # certain, so launches do not accumulate across calibration re-runs.
        server = f"{LABEL}-doris-server-{uuid4().hex}"
        sentinels: list[str] = []
        try:
            for sentinel in spec.sentinels:
                sentinels.append(start_doris_sentinel(sentinel))
            time.sleep(2)  # let each sentinel's httpd bind before the server can drive a fetch
            # Twin of doris_backend.doris_server_args (the nuisance suite's server launch), except
            # the nuisance memory bound: fold this wiring back into that helper at the next
            # acceptance reset, when this module (AST-fingerprinted into every acceptance fixture)
            # moves anyway.
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
                    *own_network_args(DORIS_BRIDGE),
                    image,
                    "--db-host",
                    DORIS_HOST,
                    "--db-port",
                    "9030",
                    "--db-user",
                    "root",
                    "--db-database",
                    DORIS_DB,
                ],
            )
        finally:
            doris_rm(server)
            for name in sentinels:
                doris_rm(name)


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
