import dataclasses
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from functools import partial
from pathlib import Path

from evals.cve.backends.kubernetes import StoodControlPlane
from evals.cve.backends.kubernetes_detection import ControlPlaneDocker, kubernetes_injection_env
from evals.cve.detection.targets import ACCEPTANCE_TARGETS, Target
from tests.fakes.planting_docker import FakePlantingDocker

CONTROL_PLANE_NETWORK = "kube-net"
KUBERNETES_TARGET = next(
    target for target in ACCEPTANCE_TARGETS if target.flaw_id == "CVE-2025-53355"
)


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
def _a_stood_control_plane(name: str, memory_bound: Sequence[str]) -> Generator[StoodControlPlane]:
    yield StoodControlPlane(CONTROL_PLANE_NETWORK, Path("/host/kubeconfig"))
