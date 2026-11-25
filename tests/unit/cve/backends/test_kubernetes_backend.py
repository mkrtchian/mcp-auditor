from pathlib import Path

import pytest

import tests.unit.cve.backends.support.test_kubernetes_backend_given as given
import tests.unit.cve.backends.support.test_kubernetes_backend_then as then
import tests.unit.support.backend_launch_specs as specs
import tests.unit.support.fake_control_planes as fake_control_planes
from evals.cve.backends.kubernetes import LIFECYCLE
from evals.cve.backends.kubernetes_detection import kubernetes_injection_env
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.docker_argv import value_after


def test_the_control_plane_runs_unprivileged_on_its_own_network(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    docker = given.a_docker_whose_control_plane_comes_up(monkeypatch, tmp_path)

    with LIFECYCLE.launch("server", "image", given.a_host(), ["serve"]):
        pass

    then.the_control_plane_runs_unprivileged_on_its_own_network(docker, docker.started()[0])


def test_the_nuisance_server_joins_its_control_plane_with_its_admin_conf_mounted_read_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    docker = given.a_docker_whose_control_plane_comes_up(monkeypatch, tmp_path)

    with LIFECYCLE.launch("server", "image", given.a_host(), ["serve"]) as server:
        assert value_after(server, "--network") == docker.created_networks()[0]
        kubeconfig = then.mounts_the_kubeconfig_read_only(server)
        then.the_kubeconfig_is_the_control_planes_admin_conf_naming_the_api_server_by_address(
            kubeconfig
        )


def test_the_control_plane_its_network_and_its_kubeconfig_are_removed_when_the_body_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    docker = given.a_docker_whose_control_plane_comes_up(monkeypatch, tmp_path)
    kubeconfigs: list[Path] = []

    with (
        pytest.raises(RuntimeError),
        LIFECYCLE.launch("server", "image", given.a_host(), []) as server,
    ):
        kubeconfigs.append(then.mounts_the_kubeconfig_read_only(server))
        raise RuntimeError("the probe failed")

    then.the_control_plane_its_network_and_its_kubeconfig_were_removed(
        docker, "server", kubeconfigs[0]
    )


def test_the_detection_launch_refuses_a_host_with_no_network(tmp_path: Path):
    control_plane = fake_control_planes.a_control_plane(tmp_path)

    with (
        pytest.raises(ValueError, match="has_network"),
        kubernetes_injection_env(
            "img",
            specs.a_spec_with_no_network(),
            docker=FakePlantingDocker(),
            control_plane=control_plane.docker(),
        ),
    ):
        pass

    assert control_plane.stood == []
