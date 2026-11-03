from pathlib import Path

import pytest

import tests.unit.support.test_cve_planting_stand_ins_given as given
import tests.unit.support.test_cve_planting_stand_ins_then as then
from evals.cve_planting import PlantingFailed, planted
from evals.cve_planting_base import STAND_IN_IMAGE, own_network_args
from tests.unit.support.test_cve_planting_then import resolver_options_in


def test_a_launch_with_a_stand_in_joins_a_holder_pinning_the_name_to_its_set_up_address(
    tmp_path: Path,
):
    directory = given.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in()
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker, stand_ins_directory=directory) as args:
        holder = given.only(docker.holders)
        assert args.network == ("--network", f"container:{holder}")
        assert f"{given.HOST}:{given.ADDRESS}" in then.added_hosts(docker.holders[holder])
        assert any(f"{given.ADDRESS}/32" in setup for setup in docker.address_setups)


def test_the_stand_in_and_its_address_setup_read_the_holders_resolver_option(tmp_path: Path):
    directory = given.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in()
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker, stand_ins_directory=directory) as args:
        holder = docker.holders[given.only(docker.holders)]
        joiners = [list(args.network), *docker.stand_ins.values(), *docker.address_setups]
        assert docker.stand_ins and docker.address_setups
        assert [resolver_options_in(joiner) for joiner in joiners] == [0] * len(joiners)
        assert resolver_options_in(holder) == 1


def test_the_stand_in_serves_its_capture_leaf_and_key_inside_the_holder_on_its_address(
    tmp_path: Path,
):
    directory = given.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in()
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker, stand_ins_directory=directory):
        holder = given.only(docker.holders)
        stand_in = docker.stand_ins[given.only(docker.stand_ins)]
        assert given.following(stand_in, "--network") == f"container:{holder}"
        assert f"BIND_ADDR={given.ADDRESS}" in stand_in
        assert stand_in[-1] == STAND_IN_IMAGE
        capture = then.mounted_content(docker, stand_in, "/stand-in/capture.json")
        assert capture == given.capture_text(directory)
        assert then.mounted_content(docker, stand_in, "/stand-in/cert.pem") == given.CERTIFICATE
        assert then.mounted_content(docker, stand_in, "/stand-in/key.pem") == given.KEY


def test_a_stand_in_on_the_address_of_a_bound_sentinel_is_refused_before_any_container(
    tmp_path: Path,
):
    directory = given.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in(endpoint_host=given.ADDRESS)
    docker = given.FakePlantingDocker()

    with (
        pytest.raises(ValueError, match=rf"^{given.HOST}: "),
        planted(spec, "image:tag", docker, stand_ins_directory=directory),
    ):
        pass

    then.nothing_left_alive(docker)
    assert docker.address_setups == []


def test_a_trust_setting_mounts_the_authority_and_points_each_named_variable_at_it(
    tmp_path: Path,
):
    directory = given.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in(trust=("FICTIONAL_CA_FILE", "OTHER_CA_FILE"))
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker, stand_ins_directory=directory) as args:
        authority = "/etc/ssl/extra-ca.pem"
        assert then.mounted_content(docker, list(args.mounts), authority) == given.AUTHORITY
        assert f"FICTIONAL_CA_FILE={authority}" in args.env
        assert f"OTHER_CA_FILE={authority}" in args.env


def test_a_stand_in_that_does_not_listen_fails_the_planting_and_leaves_nothing(tmp_path: Path):
    directory = given.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in(
        trust=("FICTIONAL_CA_FILE",), endpoint_host="198.51.100.5"
    )
    docker = given.FakePlantingDocker(dead_stand_ins=frozenset({given.ADDRESS}))

    with (
        pytest.raises(PlantingFailed, match=rf"^stand-in for {given.HOST} is not serving$"),
        planted(spec, "image:tag", docker, stand_ins_directory=directory),
    ):
        pass

    then.nothing_left_alive(docker)


def test_teardown_removes_the_stand_in_and_its_host_files(tmp_path: Path):
    directory = given.a_stand_ins_directory(tmp_path)
    spec = given.a_spec_with_the_stand_in(trust=("FICTIONAL_CA_FILE",))
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker, stand_ins_directory=directory):
        assert len(docker.stand_ins) == 1

    then.nothing_left_alive(docker)


def test_a_launch_with_no_public_names_plants_as_before_and_reads_no_file(tmp_path: Path):
    spec = given.a_spec_without_public_names()
    docker = given.FakePlantingDocker()

    with planted(spec, "image:tag", docker, stand_ins_directory=tmp_path / "absent") as args:
        network = next(iter(docker.networks))
        assert spec.needs_holder is False
        assert docker.holders == {}
        assert docker.stand_ins == {}
        assert args.network == tuple(own_network_args(network))
