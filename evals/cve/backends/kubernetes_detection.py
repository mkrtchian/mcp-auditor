"""The detection builder of the kubectl targets: the server launch of `command_injection_env`, with
the control plane of `evals.cve.backends.kubernetes` stood for the launch.

It lives apart from `kubernetes.py` because it plants through `evals.cve.environments`, which
imports `mcp_auditor`, while the dossiers copy the import closure of `kubernetes.py`.

The control plane is stood before the planting, so the planting's holder is removed before the
control plane's network, which Docker refuses to remove while a container is attached to it. When
the launch has a namespace holder, the holder joins the control plane's network and the server
reaches the API server through the holder's namespace. When it has none, the control plane's
network is the server's second network.
"""

import secrets
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass

from evals.cve.backends.kubernetes import (
    ControlPlaneStand,
    connect_to_network,
    stood_control_plane,
)
from evals.cve.environments import Launch, LaunchShape, materialise
from evals.cve.layout import layout_mount_args, owned_layout
from evals.cve.planting import PlantingDocker, PlantingSpec, confinement_args, planted
from evals.cve.planting_base import LABEL
from evals.cve.planting_docker import DOCKER_PLANTING

_HOLDER_PREFIX = "container:"


@dataclass(frozen=True)
class ControlPlaneDocker:
    stand: ControlPlaneStand
    connect: Callable[[str, str], None]  # (network, container)


DOCKER_CONTROL_PLANE = ControlPlaneDocker(stood_control_plane, connect_to_network)


@contextmanager
def kubernetes_injection_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
    control_plane: ControlPlaneDocker = DOCKER_CONTROL_PLANE,
) -> Generator[Launch]:
    if not spec.host.has_network:
        # Docker connects no network to a container on `none`, the holder's or the server's.
        raise ValueError("a kubectl target's planting host needs has_network=True")
    name = f"{LABEL}-kube-control-plane-{secrets.token_hex(6)}"
    with (
        owned_layout(docker, lambda root: materialise(root, spec, shape)) as root,
        control_plane.stand(name, ()) as stood,
        planted(spec, image, docker) as args,
    ):
        holder = _holder(args.network)
        if holder is not None:
            control_plane.connect(stood.network, holder)
        second_network = () if holder is not None else ("--network", stood.network)
        yield Launch(
            command="docker",
            args=[
                "run",
                "-i",
                "--rm",
                *confinement_args(),
                *args.run_args(),
                *second_network,
                *stood.mount_args(),
                *layout_mount_args(root, spec.host.layout_mount),
                image,
            ],
        )


def _holder(network: tuple[str, ...]) -> str | None:
    if len(network) >= 2 and network[0] == "--network" and network[1].startswith(_HOLDER_PREFIX):
        return network[1].removeprefix(_HOLDER_PREFIX)
    return None
