import ipaddress

from evals.apify_backend import (
    API_HOST,
    APIFY_BENIGN_HOST,
    APIFY_SUBNET,
    APIFY_SUFFIX_HOST,
    apify_network_args,
)
from tests.unit.support.docker_argv import values_after


def test_the_documentation_hosts_resolve_to_the_responder_address_it_is_given():
    aliases = values_after(apify_network_args("198.18.1.77"), "--add-host")

    [api_pin] = [alias for alias in aliases if alias.startswith(f"{API_HOST}:")]
    assert sorted(aliases) == sorted(
        [f"{APIFY_BENIGN_HOST}:198.18.1.77", f"{APIFY_SUFFIX_HOST}:198.18.1.77", api_pin]
    )
    stand_in_address = ipaddress.ip_address(api_pin.removeprefix(f"{API_HOST}:"))
    assert stand_in_address in ipaddress.ip_network(APIFY_SUBNET)
