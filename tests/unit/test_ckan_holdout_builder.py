import pytest

import tests.unit.support.test_ckan_holdout_builder_given as given
import tests.unit.support.test_ckan_holdout_builder_then as then
from evals.cve.backends.ckan import CKAN_BRIDGE, CKAN_PARTS
from evals.cve.backends.ckan_holdout import ckan_ssrf_env
from evals.cve.backends.doris import LINK_LOCAL_NETWORK, start_doris_sentinel
from evals.cve.layout import WORKSPACE
from evals.cve.planting_base import confinement_args, unprivileged_user_args
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.docker_argv import carries, mount_of, value_after


def test_the_server_joins_the_ckan_bridge_and_the_link_local_network():
    with given.a_launch() as launch:
        then.joins_networks(launch.args, [CKAN_BRIDGE, LINK_LOCAL_NETWORK])


def test_the_server_reaches_demo_ckan_org_on_the_front_and_trusts_the_fixture_authority():
    with given.a_launch() as launch:
        then.reaches_the_demo_portal_on_the_front_and_trusts_the_authority(launch.args)


def test_the_server_runs_confined_and_unprivileged_from_its_checkout_on_the_read_only_layout():
    with given.a_launch() as launch:
        assert carries(launch.args, confinement_args())
        assert carries(launch.args, unprivileged_user_args())
        assert value_after(launch.args, "-w") == "/srv/app"
        assert mount_of(launch.args, WORKSPACE).endswith(f":{WORKSPACE}:ro")
        assert launch.args[-1] == "img"


def test_the_launch_stands_the_stack_then_a_sentinel_per_kept_place_and_no_holder():
    ckan = given.a_ckan_docker()
    planting = FakePlantingDocker()

    with ckan_ssrf_env("img", given.the_targets_spec(), docker=planting, ckan=ckan.docker()):
        assert ckan.events == ["stack", "link-local network", "sentinel", "sentinel", "sentinel"]
        assert sorted(ckan.sentinel_hosts) == ["169.254.169.254", "169.254.170.2", "169.254.170.23"]
        assert planting.holders == {}


def test_the_launch_removes_its_server_and_its_sentinels_on_exit():
    ckan = given.a_ckan_docker()

    with ckan_ssrf_env(
        "img", given.the_targets_spec(), docker=FakePlantingDocker(), ckan=ckan.docker()
    ) as launch:
        server = value_after(launch.args, "--name")

    assert sorted(ckan.removed) == sorted([server, *(f"sentinel-{h}" for h in ckan.sentinel_hosts)])


def test_no_ckan_part_runs_on_the_network_the_sentinels_take(monkeypatch: pytest.MonkeyPatch):
    docker = given.a_recorded_docker(monkeypatch)
    [sentinel] = given.the_targets_spec().sentinels[:1]

    start_doris_sentinel(sentinel)

    then.joins_networks(docker.commands[0], [LINK_LOCAL_NETWORK])
    for part in CKAN_PARTS:
        then.joins_networks(part.run_args(), [CKAN_BRIDGE])
