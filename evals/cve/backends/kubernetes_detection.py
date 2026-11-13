"""The detection builder of the kubectl targets: the launch of `launch_beside_backend`, with the
control plane of `evals.cve.backends.kubernetes` as its backend.

It lives apart from `kubernetes.py` because it plants through `evals.cve.environments`, which
imports `mcp_auditor`, while the dossiers copy the import closure of `kubernetes.py`.
"""

import secrets
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass

from evals.cve.backends.backend_beside_launch import BackendStand, launch_beside_backend
from evals.cve.backends.kubernetes import (
    ControlPlaneStand,
    connect_to_network,
    stood_control_plane,
)
from evals.cve.environments import Launch, LaunchShape
from evals.cve.planting import PlantingDocker, PlantingSpec
from evals.cve.planting_base import LABEL
from evals.cve.planting_docker import DOCKER_PLANTING


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
    backend = BackendStand(lambda: control_plane.stand(name, ()), control_plane.connect)
    with launch_beside_backend(image, spec, shape, docker=docker, backend=backend) as launch:
        yield launch
