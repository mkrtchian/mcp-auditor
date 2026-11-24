import dataclasses
from collections.abc import Generator
from contextlib import contextmanager
from functools import partial
from pathlib import Path

from evals.cve.backends.kubernetes import StoodControlPlane
from evals.cve.backends.kubernetes_detection import ControlPlaneDocker, kubernetes_injection_env
from evals.cve.detection.targets import Target
from evals.cve.environments import Launch, LaunchShape
from evals.cve.kit.target import LaunchMode
from evals.cve.planting import PlantingSpec
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.acceptance_targets import KUBERNETES, an_acceptance_target

CONTROL_PLANE_NETWORK = "kube-net"
KUBERNETES_TARGET = an_acceptance_target(KUBERNETES)
SSRF_TARGET = an_acceptance_target("CVE-2025-65513")


def a_target_recording_its_launches(
    launch_mode: LaunchMode = LaunchMode.NORMAL,
) -> tuple[Target, list[tuple[str, PlantingSpec, LaunchShape]]]:
    calls: list[tuple[str, PlantingSpec, LaunchShape]] = []

    @contextmanager
    def recording_builder(image: str, spec: PlantingSpec, shape: LaunchShape) -> Generator[Launch]:
        calls.append((image, spec, shape))
        yield Launch("docker", [])

    target = dataclasses.replace(SSRF_TARGET, builder=recording_builder, launch_mode=launch_mode)
    return target, calls


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
