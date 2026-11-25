import ipaddress

from evals.cve.backends.apify import (
    API_HOST,
    APIFY_SUBNET,
    DOCS_HOST,
    apify_network_args,
)
from tests.unit.cve.backends.support.fixture_authority import trusts_the_fixture_authority
from tests.unit.support.docker_argv import values_after


def test_each_apify_host_resolves_to_a_stand_in_on_the_backend_subnet():
    pins = dict(alias.split(":", 1) for alias in values_after(apify_network_args(), "--add-host"))

    assert set(pins) == {DOCS_HOST, API_HOST}
    for address in pins.values():
        assert ipaddress.ip_address(address) in ipaddress.ip_network(APIFY_SUBNET)


def test_the_network_args_trust_the_fixture_authority_mounted_read_only():
    trusts_the_fixture_authority(apify_network_args(), "NODE_EXTRA_CA_CERTS", DOCS_HOST)
