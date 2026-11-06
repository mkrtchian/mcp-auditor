"""The CVE environment builders only holdout targets use, beside the acceptance builders and the
shared launch types of `cve_environments`, whose module docstring (confinement, teardown, the
orphan sweep) governs these builders too. Fingerprinted into every CVE fixture with it
(`cve_baseline.ENVIRONMENT_PATHS`).
"""

import time
from collections.abc import Generator
from contextlib import contextmanager
from uuid import uuid4

from evals.cve_environments import Launch, LaunchShape, materialise
from evals.cve_layout import layout_mount_args, owned_layout
from evals.cve_planting import PlantingDocker, PlantingSpec, confinement_args, planted
from evals.cve_planting_base import LABEL, own_network_args, unprivileged_user_args
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
from evals.n8n_instance_backend import N8N_API_URL, running_n8n_instance


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


# The no-holder launch's key: no instance runs there, the key only keeps the API tools registered
# so both arms of the layout check list the same tools.
_UNPROVISIONED_KEY = "unprovisioned"


@contextmanager
def ssrf_redirect_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    # ssrf_env plus the real n8n instance N8N_API_URL points at, co-located in the sentinels'
    # namespace holder and provisioned for this launch (n8n_instance_backend). planting() binds the
    # IP-literal sentinels inside a holder on loopback and the server joins that holder's
    # namespace, so the instance joins it too on a public-looking address the SSRF guard passes.
    # The reference arm plants no sentinel, so it joins no holder and starts no instance: launch
    # the server plainly then, exactly as ssrf_env's reference arm runs without its sentinel.
    with (
        owned_layout(docker, lambda root: materialise(root, spec, shape)) as root,
        planted(spec, image, docker) as args,
    ):
        holder_ref = args.network[1] if _joins_holder(args.network) else None
        with _n8n_api_key(holder_ref) as api_key:
            yield Launch(
                command="docker",
                args=[
                    "run",
                    "-i",
                    "--rm",
                    *confinement_args(),
                    *args.run_args(),
                    "-e",
                    f"N8N_API_URL={N8N_API_URL}",
                    "-e",
                    f"N8N_API_KEY={api_key}",
                    *layout_mount_args(root, spec.host.layout_mount),
                    image,
                ],
            )


@contextmanager
def _n8n_api_key(holder_ref: str | None) -> Generator[str]:
    if holder_ref is None:
        yield _UNPROVISIONED_KEY
        return
    with running_n8n_instance(holder_ref) as api_key:
        yield api_key


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
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    # The flaw's internal fetch runs on the Doris backend (its http() TVF), not on the server
    # container, so the sentinels sit on a static-IP link-local bridge the Doris node reaches,
    # not behind the generic planting holder, and planted() is never called: its holder's network
    # would replace the Doris bridge. The cluster is heavy (an FE+BE JVM) and persistent:
    # provisioned once and reused across exercises, only the per-launch sentinels are stood and
    # torn down here. The server runs as every target does, under the unprivileged account from
    # its host's working directory on the /srv layout, which no kept place needs.
    with (
        owned_layout(docker, lambda root: materialise(root, spec, shape)) as root,
        DORIS_LAUNCH_LOCK,
    ):
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
            # No longer a twin of doris_backend.doris_server_args (the nuisance suite's launch):
            # that one mounts no layout, the nuisance suite having none, reads its admission
            # host's user and takes the nuisance memory bound.
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
                    *unprivileged_user_args(),
                    "-w",
                    spec.host.working_directory,
                    *layout_mount_args(root, spec.host.layout_mount),
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
