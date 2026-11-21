from pathlib import Path

import pytest

import tests.unit.cve.backends.support.backend_launch_specs as specs
import tests.unit.cve.backends.support.test_kubernetes_backend_given as given
import tests.unit.cve.backends.support.test_kubernetes_backend_then as then
from evals.cve.backends.kubernetes import LIFECYCLE
from evals.cve.backends.kubernetes_detection import kubernetes_injection_env
from evals.cve.dossier_closure import import_closure
from evals.cve.nuisance.fix_checks.cve_2025_69902_kubectl import FIXTURE, kubectl_env
from tests.fakes.planting_docker import FakePlantingDocker


def test_the_backend_module_carries_no_auditor_module_into_a_dossier():
    closure = import_closure(["evals.cve.backends.kubernetes"])

    assert not [module for module in closure if module.startswith("mcp_auditor")]


def test_the_control_plane_runs_unprivileged_on_its_own_network(monkeypatch: pytest.MonkeyPatch):
    docker = given.a_docker_whose_control_plane_comes_up(monkeypatch)

    with LIFECYCLE.launch("server", "image", given.a_host(), ["serve"]):
        pass

    then.the_control_plane_runs_unprivileged_on_its_own_network(docker, docker.started()[0])


def test_the_nuisance_server_joins_its_control_plane_with_its_admin_conf_mounted_read_only(
    monkeypatch: pytest.MonkeyPatch,
):
    docker = given.a_docker_whose_control_plane_comes_up(monkeypatch)

    with LIFECYCLE.launch("server", "image", given.a_host(), ["serve"]) as server:
        then.the_server_joins_the_network_of_its_control_plane(docker, server)
        kubeconfig = then.mounts_the_kubeconfig_read_only(server)
        then.the_kubeconfig_is_the_control_planes_admin_conf_naming_the_api_server_by_address(
            kubeconfig
        )


def test_the_control_plane_its_network_and_its_kubeconfig_are_removed_when_the_body_raises(
    monkeypatch: pytest.MonkeyPatch,
):
    docker = given.a_docker_whose_control_plane_comes_up(monkeypatch)
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
    control_plane = given.a_control_plane(tmp_path)

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


def test_the_fix_check_launch_takes_the_bounded_control_planes_network_and_its_kubeconfig(
    tmp_path: Path,
):
    control_plane = given.a_control_plane(tmp_path)

    with kubectl_env(
        "img", FIXTURE.planting_spec(), docker=FakePlantingDocker(), stand=control_plane.stand
    ) as launch:
        then.the_server_takes_the_control_planes_network_as_a_second_network(launch.args)
        then.mounts_the_kubeconfig_read_only(launch.args)
        then.carries_the_witness_in_the_servers_environment(launch.args)
