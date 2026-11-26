"""Shared launch builder for the mcp-server-kubernetes fix checks.

The server shells out to kubectl, so each launch stands an upstream control plane
(`evals.cve.backends.kubernetes.stood_control_plane`) and mounts its admin.conf at kubectl's
default path. The control plane is stood before the planting, so the planting's holder is removed
before the control plane's network, which Docker refuses to remove while a container is attached.

The server reaches the control plane as a second network beside the planting's. When the planting
stands a namespace holder (a witness served on a bound address), the holder joins the control
plane's network and the server reaches it through the holder's namespace, with no second network of
its own, since the control plane never runs inside the holder. This is the logic of
`evals.cve.backends.backend_beside_launch.launch_beside_backend`, which the kit cannot import
because it imports `evals.cve.environments`.
"""

import secrets
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import replace

from evals.cve.backends.kubernetes import (
    ControlPlaneStand,
    connect_to_network,
    stood_control_plane,
)
from evals.cve.kit.launch import Launch, LaunchShape
from evals.cve.planting import PlantingDocker, PlantingSpec, confinement_args, planted
from evals.cve.planting_base import own_network_args
from evals.cve.planting_docker import DOCKER_PLANTING

LAUNCH = ("mcp-server-kubernetes",)
_HOLDER_PREFIX = "container:"

# (network, container) -> connects the control plane network to the holder.
type Connect = Callable[[str, str], None]


@contextmanager
def kube_server_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
    stand: ControlPlaneStand = stood_control_plane,
    connect: Connect = connect_to_network,
) -> Generator[Launch]:
    name = f"mcp-auditor-kit-kube-control-plane-{secrets.token_hex(4)}"
    with stand(name) as control_plane, planted(spec, image, docker) as args:
        args = replace(args, network=_server_network(args.network, control_plane.network, connect))
        yield Launch(
            command="docker",
            args=[
                "run", "-i", "--rm",
                *confinement_args(),
                *control_plane.mount_args(),
                *args.run_args(),
                image,
                *LAUNCH,
            ],
        )  # fmt: skip


def _server_network(
    planted_network: tuple[str, ...], control_plane_network: str, connect: Connect
) -> tuple[str, ...]:
    holder = _holder(planted_network)
    if holder is not None:
        connect(control_plane_network, holder)
        return planted_network
    base = planted_network[1] if len(planted_network) >= 2 else "none"
    own_network = tuple(own_network_args(control_plane_network))
    return own_network if base == "none" else ("--network", base, *own_network)


def _holder(network: tuple[str, ...]) -> str | None:
    if len(network) >= 2 and network[0] == "--network" and network[1].startswith(_HOLDER_PREFIX):
        return network[1].removeprefix(_HOLDER_PREFIX)
    return None
