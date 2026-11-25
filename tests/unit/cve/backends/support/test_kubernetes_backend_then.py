import stat
from collections.abc import Sequence
from pathlib import Path

from evals.cve.backends.kubernetes import CONTROL_PLANE_IMAGE, CONTROL_PLANE_NETWORK, KUBECONFIG
from evals.cve.nuisance.fix_checks.cve_2025_69902_kubectl import WITNESS
from evals.cve.planting_base import unprivileged_user_args
from tests.fakes import ScriptedDockerExecutable
from tests.unit.support.docker_argv import carries, mount_of, value_after, values_after
from tests.unit.support.fake_control_planes import ADMIN_CONF, API_SERVER


def the_control_plane_runs_unprivileged_on_its_own_network(
    docker: ScriptedDockerExecutable, control_plane: Sequence[str]
) -> None:
    networks = values_after(control_plane, "--network")
    assert networks == docker.created_networks()
    assert networks[0].startswith(f"{CONTROL_PLANE_NETWORK}-")
    assert carries(control_plane, unprivileged_user_args())
    assert control_plane[-1] == CONTROL_PLANE_IMAGE


def mounts_the_kubeconfig_read_only(server: Sequence[str]) -> Path:
    host_path, container_path, mode = mount_of(server, KUBECONFIG).split(":")
    assert (container_path, mode) == (KUBECONFIG, "ro")
    return Path(host_path)


def the_kubeconfig_is_the_control_planes_admin_conf_naming_the_api_server_by_address(
    kubeconfig: Path,
) -> None:
    assert kubeconfig.read_text() == ADMIN_CONF
    assert f"server: {API_SERVER}" in kubeconfig.read_text()
    assert stat.S_IMODE(kubeconfig.stat().st_mode) == 0o644


def the_server_joins_the_network_of_its_control_plane(
    docker: ScriptedDockerExecutable, server: Sequence[str]
) -> None:
    assert value_after(server, "--network") == docker.created_networks()[0]


def the_control_plane_its_network_and_its_kubeconfig_were_removed(
    docker: ScriptedDockerExecutable, server: str, kubeconfig: Path
) -> None:
    removed = docker.removed()
    assert server in removed
    assert value_after(docker.started()[0], "--name") in removed
    assert docker.created_networks()[0] in removed
    assert not kubeconfig.exists()


def the_server_takes_the_control_planes_network_as_a_second_network(server: Sequence[str]) -> None:
    networks = values_after(server, "--network")
    assert len(networks) == 2
    assert networks[1] == "kube-net-1"


def carries_the_witness_in_the_servers_environment(server: Sequence[str]) -> None:
    assert any(
        value.startswith(f"{WITNESS.coordinates.name}=") for value in values_after(server, "-e")
    )
