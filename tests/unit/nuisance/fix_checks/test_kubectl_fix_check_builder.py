from pathlib import Path

import tests.unit.support.fake_control_planes as fake_control_planes
from evals.cve.backends.kubernetes import KUBECONFIG
from evals.cve.nuisance.fix_checks.cve_2025_69902_kubectl import FIXTURE, WITNESS, kubectl_env
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.docker_argv import mount_of, values_after


def test_the_fix_check_launch_takes_the_bounded_control_planes_network_and_its_kubeconfig(
    tmp_path: Path,
):
    control_plane = fake_control_planes.a_control_plane(tmp_path)

    with kubectl_env(
        "img", FIXTURE.planting_spec(), docker=FakePlantingDocker(), stand=control_plane.stand
    ) as launch:
        assert values_after(launch.args, "--network")[1:] == control_plane.networks
        assert mount_of(launch.args, KUBECONFIG) == f"{control_plane.kubeconfig}:{KUBECONFIG}:ro"
        assert any(
            value.startswith(f"{WITNESS.coordinates.name}=")
            for value in values_after(launch.args, "-e")
        )
