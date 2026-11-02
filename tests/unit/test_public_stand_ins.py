from pathlib import Path

import pytest
from pydantic import ValidationError

import tests.unit.support.test_public_stand_ins_given as given
from evals.cve_planting_base import StandIn
from evals.public_stand_ins import STAND_INS_DIRECTORY, StandInFiles, stand_in, stand_in_files


def test_a_capture_loads_with_its_leaf_key_and_authority(tmp_path: Path):
    directory = given.a_stand_in_directory(tmp_path)

    loaded = stand_in(given.HOST, directory)

    assert loaded == StandIn(
        host=given.HOST,
        address="93.184.215.14",
        capture=(directory / f"{given.HOST}.json").read_text(),
        certificate="leaf",
        key="key",
        authority="authority",
    )


def test_a_capture_naming_another_host_than_its_file_is_refused(tmp_path: Path):
    directory = given.a_stand_in_directory(tmp_path, host="www.example.com")

    with pytest.raises(ValueError, match=r"host is www\.example\.com"):
        stand_in(given.HOST, directory)


@pytest.mark.parametrize("address", ["10.0.0.7", "127.0.0.1", "198.18.0.1", "198.19.255.1"])
def test_an_address_that_is_not_global_unicast_is_refused(tmp_path: Path, address: str):
    directory = given.a_stand_in_directory(tmp_path, address=address)

    with pytest.raises(ValidationError, match="address"):
        stand_in(given.HOST, directory)


def test_a_route_scheme_other_than_http_or_https_is_refused(tmp_path: Path):
    directory = given.a_stand_in_directory(tmp_path, routes=[given.a_route("ftp")])

    with pytest.raises(ValidationError, match="scheme"):
        stand_in(given.HOST, directory)


@pytest.mark.parametrize("field", ["command", "captured_at"])
def test_an_empty_provenance_field_is_refused(tmp_path: Path, field: str):
    directory = given.a_stand_in_directory(tmp_path, **{field: ""})

    with pytest.raises(ValidationError, match=field):
        stand_in(given.HOST, directory)


def test_the_files_of_a_stand_in_are_named_without_being_read(tmp_path: Path):
    files = stand_in_files(given.HOST, tmp_path)

    assert files == StandInFiles(
        capture=tmp_path / "example.com.json",
        certificate=tmp_path / "tls" / "example.com.pem",
        key=tmp_path / "tls" / "example.com-key.pem",
        authority=tmp_path / "tls" / "fixture-authority.pem",
    )


def test_every_committed_capture_loads_with_its_leaf():
    hosts = [path.stem for path in STAND_INS_DIRECTORY.glob("*.json")]

    loaded = [stand_in(host) for host in hosts]

    assert all(each.certificate.startswith("-----BEGIN CERTIFICATE-----") for each in loaded)


def test_the_committed_authority_signs_for_exactly_the_https_stand_in_hosts():
    hosts = given.committed_https_hosts(STAND_INS_DIRECTORY)

    critical, permitted, excluded = given.committed_authority_constraints(STAND_INS_DIRECTORY)

    assert critical
    assert permitted == hosts
    assert excluded == {f".{host}" for host in hosts}


def test_every_committed_leaf_names_an_https_stand_in_host():
    hosts = given.committed_https_hosts(STAND_INS_DIRECTORY)

    leaves = given.committed_leaf_names(STAND_INS_DIRECTORY)

    assert {name: names for name, names in leaves.items() if not names <= hosts} == {}
    assert all(len(names) == 1 for names in leaves.values())
