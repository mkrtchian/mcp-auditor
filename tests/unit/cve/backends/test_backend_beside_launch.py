import tests.unit.cve.backends.support.backend_launch_specs as specs
import tests.unit.cve.backends.support.test_backend_beside_launch_given as given
from evals.cve.layout import WORKSPACE
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.docker_argv import mount_of, values_after


def test_the_holder_joins_the_backends_network():
    planting = FakePlantingDocker()
    stand = given.FakeBackendStand(planting)

    with given.a_launch_beside(stand, specs.a_spec_with_a_holder()) as launch:
        [holder] = planting.holders
        assert stand.connected == [(given.BACKEND_NETWORK, holder)]
        assert values_after(launch.args, "--network") == [f"container:{holder}"]


def test_without_a_holder_the_backends_network_is_the_servers_second_network():
    planting = FakePlantingDocker()
    stand = given.FakeBackendStand(planting)

    with given.a_launch_beside(stand, specs.a_spec_without_a_holder()) as launch:
        networks = values_after(launch.args, "--network")
        assert len(networks) == 2
        assert networks[1] == given.BACKEND_NETWORK
        assert stand.connected == []


def test_the_holder_is_removed_before_the_backend():
    planting = FakePlantingDocker()
    stand = given.FakeBackendStand(planting)

    with given.a_launch_beside(stand, specs.a_spec_with_a_holder()):
        pass

    assert stand.holders_at_removal == [[]]


def test_the_layout_and_the_backends_files_are_mounted_read_only():
    planting = FakePlantingDocker()
    stand = given.FakeBackendStand(planting)

    with given.a_launch_beside(stand, specs.a_spec_with_a_holder()) as launch:
        assert mount_of(launch.args, WORKSPACE).endswith(f":{WORKSPACE}:ro")
        assert mount_of(launch.args, given.BACKEND_MOUNT).endswith(":ro")
