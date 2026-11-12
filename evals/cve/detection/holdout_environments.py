"""The environment builders only holdout targets use, beside the acceptance builders and the
shared launch types of `evals.cve.environments`, whose module docstring (confinement, teardown,
the orphan sweep) governs these builders too. Fingerprinted into every detection fixture with it
(`evals.cve.detection.baseline.ENVIRONMENT_PATHS`).
"""

import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from evals.cve.backends.doris import (
    DORIS_BRIDGE,
    DORIS_LAUNCH_LOCK,
    DORIS_SERVER_LAUNCH,
    doris_rm,
    ensure_doris,
    start_doris_sentinel,
)
from evals.cve.backends.n8n_instance import N8N_API_URL, running_n8n_instance
from evals.cve.environments import (
    CHECKOUT,
    PROJECT,
    Launch,
    LaunchShape,
    filesystem_launch,
    materialise,
)
from evals.cve.layout import layout_mount_args, owned_layout
from evals.cve.planting import PlantingDocker, PlantingSpec, confinement_args, planted
from evals.cve.planting_base import LABEL, own_network_args, unprivileged_user_args
from evals.cve.planting_docker import DOCKER_PLANTING


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
    # not pointed at a directory), so the launch is the /srv mount and the planting code's args,
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


@contextmanager
def filesystem_scope_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    # filesystem_env without its leak<i>/report links: those lie inside the layout and lead to a
    # kept place, while the exploits of a scope-carrying server name each place by absolute path.
    with (
        owned_layout(docker, lambda root: materialise(root, spec, shape)) as root,
        planted(spec, image, docker) as args,
    ):
        yield filesystem_launch(layout_mount_args(root, spec.host.layout_mount), image, args)


@contextmanager
def command_injection_checkout_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
) -> Generator[Launch]:
    # command_injection_env for a server whose start creates ./captures, its documented capture
    # directory, in its working directory: run from the read-only checkout, it needs the
    # directory to exist already, so the tree carries it empty.
    with (
        owned_layout(docker, lambda root: _materialise_with_captures(root, spec, shape)) as root,
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


def _materialise_with_captures(root: Path, spec: PlantingSpec, shape: LaunchShape) -> None:
    # The reference arm carries it too, so the server starts there and the break check compares.
    materialise(root, spec, shape)
    (root / CHECKOUT / "captures").mkdir()


# The @houtini/lm server reads caller-chosen paths through the OpenAI-compatible endpoint of the
# llama-server baked on the image's loopback. HOUTINI_LM_FILE_ROOTS names the scope the patched
# version confines reads to (the checkout), and HOUTINI_LM_ENDPOINT_URL points at that in-image
# inference server, so the launch adds only those two variables over command_injection_env.
_HOUTINI_ENDPOINT_URL = "http://127.0.0.1:1234"


@contextmanager
def houtini_lm_env(
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
                "-e",
                f"HOUTINI_LM_FILE_ROOTS={PROJECT}",
                "-e",
                f"HOUTINI_LM_ENDPOINT_URL={_HOUTINI_ENDPOINT_URL}",
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
    # The self-contained MySQL-MCP image carries its own engine, started by the entrypoint, and its
    # AWS lookups reach the planting code's stand-ins, so the launch adds nothing but the frozen
    # /srv layout (ADR 031).
    # The server takes no scope argument, so none is appended after the image;
    # the network isolation, the planted file mounts, the planted env and the hostname all come
    # from the planting code's PlantedArgs.
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
        # certain, so launches do not accumulate across calibration check runs.
        server = f"{LABEL}-doris-server-{uuid4().hex}"
        sentinels: list[str] = []
        try:
            for sentinel in spec.sentinels:
                sentinels.append(start_doris_sentinel(sentinel))
            time.sleep(2)  # let each sentinel's httpd bind before the server can drive a fetch
            # The server options are the nuisance suite's launch, DORIS_SERVER_LAUNCH: the two
            # launches carry the same server options, diverging only in the docker run options
            # (this one mounts the /srv layout and runs unprivileged, the nuisance one mounts no
            # layout, reads its admission host's user and takes the nuisance memory bound).
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
                    *DORIS_SERVER_LAUNCH,
                ],
            )
        finally:
            doris_rm(server)
            for name in sentinels:
                doris_rm(name)


def _joins_holder(network: tuple[str, ...]) -> bool:
    return len(network) >= 2 and network[0] == "--network" and network[1].startswith("container:")
