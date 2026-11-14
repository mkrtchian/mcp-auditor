import ipaddress

from evals.cve.backends.apify import (
    API_HOST,
    APIFY_BENIGN_HOST,
    APIFY_SUBNET,
    apify_network_args,
)
from tests.unit.support.docker_argv import environment, values_after


def test_each_documentation_host_resolves_to_a_stand_in_on_the_backend_subnet():
    pins = dict(alias.split(":", 1) for alias in values_after(apify_network_args(), "--add-host"))

    assert set(pins) == {APIFY_BENIGN_HOST, API_HOST}
    for address in pins.values():
        assert ipaddress.ip_address(address) in ipaddress.ip_network(APIFY_SUBNET)


def test_the_server_trusts_the_fixture_authority_instead_of_skipping_verification():
    env = environment(apify_network_args())

    assert "NODE_EXTRA_CA_CERTS" in env
    assert "NODE_TLS_REJECT_UNAUTHORIZED" not in env


def test_the_token_is_the_readme_placeholder():
    assert environment(apify_network_args())["APIFY_TOKEN"] == "your-apify-token"
