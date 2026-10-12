import pytest

import tests.unit.support.test_cve_planting_given as given
from evals.cve_planting import PlantingFailed, planted
from evals.cve_planting_spec import RESERVED_NAME_BLOCK, served_file


def test_a_name_host_on_a_launch_with_a_network_is_an_alias_on_the_bridge_with_no_holder():
    spec = given.spec_of(
        [given.endpoint_place(host="fictional-service", path="/p")],
        host=given.unprivileged_host(has_network=True),
    )
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker) as args:
        assert spec.needs_holder is False
        assert docker.holders == {}
        network = next(iter(docker.networks))
        sentinel = docker.sentinels[given.only(docker.sentinels)]
        assert given.following(sentinel, "--network") == network
        assert given.following(sentinel, "--network-alias") == "fictional-service"
        assert args.network == ("--network", network)


def test_an_ip_literal_host_yields_a_holder_address_setup_sentinel_and_target_network_args():
    spec = given.spec_of(
        [given.endpoint_place(host="198.51.100.5", path="/p")],
        host=given.unprivileged_host(has_network=True),
    )
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker) as args:
        network = next(iter(docker.networks))
        holder = given.only(docker.holders)
        assert given.following(docker.holders[holder], "--network") == network
        setup = given.only_list(docker.address_setups)
        assert "NET_ADMIN" in setup and "--cap-drop" in setup
        assert "198.51.100.5/32" in setup
        sentinel = given.only(docker.sentinels)
        assert given.following(docker.sentinels[sentinel], "--network") == f"container:{holder}"
        assert "NET_BIND_SERVICE" in docker.sentinels[sentinel]
        assert "BIND_ADDR=198.51.100.5" in docker.sentinels[sentinel]
        assert args.network == ("--network", f"container:{holder}")


def test_an_ip_literal_host_without_network_holds_on_network_none():
    spec = given.spec_of(
        [given.endpoint_place(host="198.51.100.5")], host=given.unprivileged_host()
    )
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker) as args:
        assert docker.networks == set()
        holder = given.only(docker.holders)
        assert given.following(docker.holders[holder], "--network") == "none"
        assert args.network == ("--network", f"container:{holder}")


def test_two_ip_literal_hosts_share_one_holder():
    spec = given.spec_of(
        [
            given.endpoint_place("endpoint-1", host="198.51.100.5"),
            given.endpoint_place("endpoint-2", host="203.0.113.7"),
        ],
        host=given.unprivileged_host(has_network=True),
    )
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker):
        assert len(docker.holders) == 1
        assert len(docker.sentinels) == 2
        assert len(docker.address_setups) == 2


def test_a_loopback_literal_and_localhost_yield_a_holder_and_no_address_setup():
    spec = given.spec_of(
        [
            given.endpoint_place("endpoint-1", host="127.0.0.5"),
            given.endpoint_place("endpoint-2", host="localhost"),
        ],
        host=given.unprivileged_host(has_network=True),
    )
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker):
        assert len(docker.holders) == 1
        assert docker.address_setups == []
        bound = {
            given.following(args, "-e", prefix="BIND_ADDR=") for args in docker.sentinels.values()
        }
        assert bound == {"BIND_ADDR=127.0.0.5", "BIND_ADDR=127.0.0.1"}


def test_a_name_host_without_network_adds_a_reserved_address_and_binds_the_sentinel_to_it():
    reserved = str(RESERVED_NAME_BLOCK.network_address + 1)
    spec = given.spec_of(
        [given.endpoint_place(host="internal.fictional")], host=given.unprivileged_host()
    )

    assert spec.host_entries == (("internal.fictional", reserved),)
    assert spec.address_setups == (reserved,)
    docker = given.FakePlantingDocker()
    with planted(spec, "image:tag", docker):
        holder = given.only(docker.holders)
        assert "--add-host" in docker.holders[holder]
        assert (
            given.following(docker.holders[holder], "--add-host")
            == f"internal.fictional:{reserved}"
        )
        sentinel = given.only(docker.sentinels)
        assert f"BIND_ADDR={reserved}" in docker.sentinels[sentinel]


def test_a_sentinel_is_told_the_file_httpd_serves_the_path_from():
    spec = given.spec_of([given.endpoint_place(host="198.51.100.5", path="/fictional/dir/")])
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker):
        sentinel = docker.sentinels[given.only(docker.sentinels)]
        assert f"SERVE_FILE={served_file('/fictional/dir/')}" in sentinel
        assert not any(arg.startswith("SERVE_PATH=") for arg in sentinel)


def test_two_holder_bound_name_hosts_differing_only_in_case_raise_and_leave_nothing_alive():
    # Built directly, past the loader's lower-casing: the second name resolves to the first
    # sentinel, so a probe by name reads it as not serving.
    spec = given.spec_of(
        [
            given.endpoint_place("endpoint-1", host="meta.fict"),
            given.endpoint_place("endpoint-2", host="META.fict"),
        ],
        host=given.unprivileged_host(),
    )
    docker = given.FakePlantingDocker()

    with pytest.raises(PlantingFailed), planted(spec, "image:tag", docker):
        pass

    assert docker.networks == set()
    assert docker.holders == {}
    assert docker.sentinels == {}


def test_an_upper_case_localhost_without_network_raises():
    spec = given.spec_of([given.endpoint_place(host="LOCALHOST")], host=given.unprivileged_host())
    docker = given.FakePlantingDocker()

    with pytest.raises(PlantingFailed), planted(spec, "image:tag", docker):
        pass

    assert docker.networks == set()
    assert docker.holders == {}
    assert docker.sentinels == {}


def test_one_network_without_a_fixed_subnet_is_created_per_launch_with_a_network():
    with_network = given.spec_of(
        [given.file_place()], host=given.unprivileged_host(has_network=True)
    )
    without = given.spec_of([given.file_place()], host=given.unprivileged_host())

    docker_a = given.FakePlantingDocker()
    with planted(with_network, "image:tag", docker_a):
        assert len(docker_a.networks) == 1  # create_network takes no subnet, so none is fixed
    docker_b = given.FakePlantingDocker()
    with planted(without, "image:tag", docker_b):
        assert docker_b.networks == set()
