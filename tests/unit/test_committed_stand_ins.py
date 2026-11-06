import tests.unit.support.test_committed_stand_ins_given as given
import tests.unit.support.test_committed_stand_ins_then as then
from evals.public_stand_ins import STAND_INS_DIRECTORY, stand_in


def test_every_committed_capture_loads_with_its_leaf():
    hosts = [path.stem for path in STAND_INS_DIRECTORY.glob("*.json")]

    loaded = [stand_in(host) for host in hosts]

    assert all(each.certificate.startswith("-----BEGIN CERTIFICATE-----") for each in loaded)


def test_the_committed_captures_are_exactly_the_declared_stand_ins():
    captured = {path.stem for path in STAND_INS_DIRECTORY.glob("*.json")}

    assert captured == given.declared_stand_in_hosts()


def test_a_pending_stand_in_host_has_a_committed_capture_and_no_declaring_target():
    captured = {path.stem for path in STAND_INS_DIRECTORY.glob("*.json")}

    assert given.PENDING_STAND_IN_HOSTS.issubset(captured)
    assert given.PENDING_STAND_IN_HOSTS.isdisjoint(given.target_declared_hosts())


def test_the_committed_authority_signs_for_exactly_the_https_stand_in_hosts():
    hosts = given.committed_https_hosts(STAND_INS_DIRECTORY)

    critical, permitted, excluded = given.committed_authority_constraints(STAND_INS_DIRECTORY)

    assert critical
    assert permitted == {given.host_subtree(host) for host in hosts}
    assert excluded == {f".{host}" for host in hosts if not given.is_ip_literal(host)}


def test_the_committed_authority_permits_an_ip_literal_host_as_its_single_address():
    hosts = given.committed_https_hosts(STAND_INS_DIRECTORY)

    _, permitted, excluded = given.committed_authority_constraints(STAND_INS_DIRECTORY)

    assert "45.55.0.10" in hosts
    assert "45.55.0.10/32" in permitted
    assert not any("/" in name for name in excluded)


def test_every_committed_leaf_names_an_https_stand_in_host():
    hosts = given.committed_https_hosts(STAND_INS_DIRECTORY)

    leaves = given.committed_leaf_names(STAND_INS_DIRECTORY)

    then.each_leaf_names_exactly_one_of(leaves, hosts)


def test_an_ip_literal_leaf_names_its_address_and_carries_no_common_name():
    leaves = given.committed_leaf_names(STAND_INS_DIRECTORY)

    common_names = given.committed_leaf_common_names(STAND_INS_DIRECTORY)

    assert leaves["45.55.0.10.pem"] == {"45.55.0.10"}
    assert common_names["45.55.0.10.pem"] == []
