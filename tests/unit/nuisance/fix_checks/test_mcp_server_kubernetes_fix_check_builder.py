from pathlib import Path

import tests.unit.support.backend_launch_specs as specs
import tests.unit.support.fake_control_planes as fake_control_planes
from evals.cve.backends.kubernetes import KUBECONFIG
from evals.cve.nuisance.fix_checks.mcp_server_kubernetes_fix_check import LAUNCH, kube_server_env
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.docker_argv import mount_of, values_after


def test_without_a_holder_the_control_planes_network_is_the_servers_second_network(tmp_path: Path):
    control_plane = fake_control_planes.a_control_plane(tmp_path)

    with kube_server_env(
        "img",
        specs.a_spec_without_a_holder(),
        docker=FakePlantingDocker(),
        stand=control_plane.stand,
        connect=control_plane.connect,
    ) as launch:
        networks = values_after(launch.args, "--network")
        assert len(networks) == 2
        assert networks[1:] == control_plane.networks
        assert control_plane.connected == []
        assert launch.args[-len(LAUNCH) - 1 :] == ["img", *LAUNCH]
        assert mount_of(launch.args, KUBECONFIG) == f"{control_plane.kubeconfig}:{KUBECONFIG}:ro"


def test_on_a_host_with_no_network_the_control_planes_network_is_the_servers_only_one(
    tmp_path: Path,
):
    control_plane = fake_control_planes.a_control_plane(tmp_path)

    with kube_server_env(
        "img",
        specs.an_empty_spec(),
        docker=FakePlantingDocker(),
        stand=control_plane.stand,
        connect=control_plane.connect,
    ) as launch:
        assert values_after(launch.args, "--network") == control_plane.networks
        assert control_plane.connected == []
        assert launch.args[-len(LAUNCH) - 1 :] == ["img", *LAUNCH]


def test_with_a_holder_the_holder_joins_the_control_planes_network(tmp_path: Path):
    control_plane = fake_control_planes.a_control_plane(tmp_path)
    planting = FakePlantingDocker()

    with kube_server_env(
        "img",
        specs.a_spec_with_a_holder(),
        docker=planting,
        stand=control_plane.stand,
        connect=control_plane.connect,
    ) as launch:
        [holder] = planting.holders
        [network] = control_plane.networks
        assert control_plane.connected == [(network, holder)]
        assert values_after(launch.args, "--network") == [f"container:{holder}"]
        assert launch.args[-len(LAUNCH) - 1 :] == ["img", *LAUNCH]
        assert mount_of(launch.args, KUBECONFIG) == f"{control_plane.kubeconfig}:{KUBECONFIG}:ro"
