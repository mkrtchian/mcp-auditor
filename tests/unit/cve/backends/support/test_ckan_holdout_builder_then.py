from collections.abc import Sequence

from evals.cve.backends.ckan import CKAN_FRONT_IP
from tests.unit.cve.backends.support.fixture_authority import trusts_the_fixture_authority
from tests.unit.support.docker_argv import values_after


def joins_networks(args: Sequence[str], networks: list[str]) -> None:
    assert values_after(args, "--network") == networks
    assert not [arg for arg in args if arg.startswith("container:")]


def reaches_the_demo_portal_on_the_front_and_trusts_the_authority(args: Sequence[str]) -> None:
    assert values_after(args, "--add-host") == [f"demo.ckan.org:{CKAN_FRONT_IP}"]
    trusts_the_fixture_authority(args, "NODE_EXTRA_CA_CERTS", "demo.ckan.org")
