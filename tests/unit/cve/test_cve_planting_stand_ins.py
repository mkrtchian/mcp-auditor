from pathlib import Path

import pytest

import tests.unit.cve.support.test_cve_planting_stand_ins_given as given
import tests.unit.cve.support.test_cve_planting_stand_ins_then as then
import tests.unit.support.fictional_planting as planting
import tests.unit.support.fictional_stand_ins as stand_ins
from evals.cve.planting import PlantingFailed, planted
from evals.cve.planting_base import (
    STAND_IN_IMAGE,
    memory_bound_args,
    own_network_args,
    resolver_args,
)
from tests.fakes.planting_docker import FakePlantingDocker
from tests.unit.support.docker_argv import carries, count
from tests.unit.support.fictional_planting import nothing_left_alive


def test_a_launch_with_a_stand_in_joins_a_holder_pinning_the_name_to_its_set_up_address(
    tmp_path: Path,
):
    directory = stand_ins.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in()
    docker = FakePlantingDocker()

    with planted(spec, "image:tag", docker, stand_ins_directory=directory) as args:
        holder = planting.only(docker.holders)
        assert args.network == ("--network", f"container:{holder}")
        assert f"{stand_ins.HOST}:{stand_ins.ADDRESS}" in then.added_hosts(docker.holders[holder])
        assert any(f"{stand_ins.ADDRESS}/32" in setup for setup in docker.address_setups)


def test_the_stand_in_and_its_address_setup_read_the_holders_resolver_option(tmp_path: Path):
    directory = stand_ins.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in()
    docker = FakePlantingDocker()

    with planted(spec, "image:tag", docker, stand_ins_directory=directory) as args:
        holder = docker.holders[planting.only(docker.holders)]
        joiners = [list(args.network), *docker.stand_ins.values(), *docker.address_setups]
        assert docker.stand_ins and docker.address_setups
        assert [count(joiner, resolver_args()) for joiner in joiners] == [0] * len(joiners)
        assert count(holder, resolver_args()) == 1


def test_the_stand_in_serves_its_capture_leaf_and_key_inside_the_holder_on_its_address(
    tmp_path: Path,
):
    directory = stand_ins.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in()
    docker = FakePlantingDocker()

    with planted(spec, "image:tag", docker, stand_ins_directory=directory):
        holder = planting.only(docker.holders)
        stand_in = docker.stand_ins[planting.only(docker.stand_ins)]
        assert planting.following(stand_in, "--network") == f"container:{holder}"
        assert f"BIND_ADDR={stand_ins.ADDRESS}" in stand_in
        assert stand_in[-1] == STAND_IN_IMAGE
        capture = then.mounted_content(docker, stand_in, "/stand-in/capture.json")
        assert capture == given.capture_text(directory)
        assert then.mounted_content(docker, stand_in, "/stand-in/cert.pem") == stand_ins.CERTIFICATE
        assert then.mounted_content(docker, stand_in, "/stand-in/key.pem") == stand_ins.KEY


def test_the_stand_in_runs_under_the_memory_bound(tmp_path: Path):
    directory = stand_ins.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in()
    docker = FakePlantingDocker()

    with planted(spec, "image:tag", docker, stand_ins_directory=directory):
        stand_in = docker.stand_ins[planting.only(docker.stand_ins)]
        assert carries(stand_in, memory_bound_args())


def test_a_stand_in_on_the_address_of_a_bound_sentinel_is_refused_before_any_container(
    tmp_path: Path,
):
    directory = stand_ins.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in(endpoint_host=stand_ins.ADDRESS)
    docker = FakePlantingDocker()

    with (
        pytest.raises(ValueError, match=rf"^{stand_ins.HOST}: "),
        planted(spec, "image:tag", docker, stand_ins_directory=directory),
    ):
        pass

    nothing_left_alive(docker)
    assert docker.address_setups == []


def test_a_trust_setting_mounts_the_authority_and_points_each_named_variable_at_it(
    tmp_path: Path,
):
    directory = stand_ins.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in(trust=("FICTIONAL_CA_FILE", "OTHER_CA_FILE"))
    docker = FakePlantingDocker()

    with planted(spec, "image:tag", docker, stand_ins_directory=directory) as args:
        authority = "/etc/ssl/extra-ca.pem"
        assert then.mounted_content(docker, list(args.mounts), authority) == stand_ins.AUTHORITY
        assert f"FICTIONAL_CA_FILE={authority}" in args.env
        assert f"OTHER_CA_FILE={authority}" in args.env


def test_a_stand_in_that_does_not_listen_fails_the_planting_and_leaves_nothing(tmp_path: Path):
    directory = stand_ins.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in(
        trust=("FICTIONAL_CA_FILE",), endpoint_host="198.51.100.5"
    )
    docker = FakePlantingDocker(dead_stand_ins=frozenset({stand_ins.ADDRESS}))

    with (
        pytest.raises(PlantingFailed, match=rf"^stand-in for {stand_ins.HOST} is not serving$"),
        planted(spec, "image:tag", docker, stand_ins_directory=directory),
    ):
        pass

    nothing_left_alive(docker)


def test_teardown_removes_the_stand_in_and_its_host_files(tmp_path: Path):
    directory = stand_ins.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in(trust=("FICTIONAL_CA_FILE",))
    docker = FakePlantingDocker()

    with planted(spec, "image:tag", docker, stand_ins_directory=directory):
        assert len(docker.stand_ins) == 1

    nothing_left_alive(docker)


def test_a_launch_with_no_public_names_plants_as_before_and_reads_no_file(tmp_path: Path):
    spec = given.a_spec_without_public_names()
    docker = FakePlantingDocker()

    with planted(spec, "image:tag", docker, stand_ins_directory=tmp_path / "absent") as args:
        network = next(iter(docker.networks))
        assert spec.needs_holder is False
        assert docker.holders == {}
        assert docker.stand_ins == {}
        assert args.network == tuple(own_network_args(network))
