import dataclasses
from collections.abc import Generator
from contextlib import contextmanager
from functools import partial
from pathlib import Path

from evals.cve.backends.kubernetes import StoodControlPlane
from evals.cve.backends.kubernetes_detection import ControlPlaneDocker, kubernetes_injection_env
from evals.cve.detection.targets import Target
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.acceptance_targets import KUBERNETES, an_acceptance_target

CONTROL_PLANE_NETWORK = "kube-net"
KUBERNETES_TARGET = an_acceptance_target(KUBERNETES)


def the_kubernetes_target_without_docker() -> Target:
    """The kubernetes target's builder on fake ports, so its layout hand-over and its control
    plane make no Docker call."""
    return dataclasses.replace(
        KUBERNETES_TARGET,
        builder=partial(
            kubernetes_injection_env,
            docker=FakePlantingDocker(),
            control_plane=ControlPlaneDocker(_a_stood_control_plane, lambda _network, _id: None),
        ),
    )


@contextmanager
def _a_stood_control_plane(name: str) -> Generator[StoodControlPlane]:
    yield StoodControlPlane(CONTROL_PLANE_NETWORK, Path("/host/kubeconfig"))
