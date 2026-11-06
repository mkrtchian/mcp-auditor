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


def test_the_committed_authority_signs_for_exactly_the_https_stand_in_hosts():
    hosts = given.committed_https_hosts(STAND_INS_DIRECTORY)

    critical, permitted, excluded = given.committed_authority_constraints(STAND_INS_DIRECTORY)

    assert critical
    assert permitted == hosts
    assert excluded == {f".{host}" for host in hosts}


def test_every_committed_leaf_names_an_https_stand_in_host():
    hosts = given.committed_https_hosts(STAND_INS_DIRECTORY)

    leaves = given.committed_leaf_names(STAND_INS_DIRECTORY)

    then.each_leaf_names_exactly_one_of(leaves, hosts)
