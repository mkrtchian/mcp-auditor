from collections.abc import Sequence

from evals.cve.backends.ckan import CKAN_FRONT_IP
from evals.cve.public_stand_ins import stand_in_files
from tests.unit.support.docker_argv import environment, mount_of, values_after

_AUTHORITY = "/etc/ssl/extra-ca.pem"


def joins_networks(args: Sequence[str], networks: list[str]) -> None:
    assert values_after(args, "--network") == networks
    assert not [arg for arg in args if arg.startswith("container:")]


def reaches_the_demo_portal_on_the_front_and_trusts_the_authority(args: Sequence[str]) -> None:
    assert values_after(args, "--add-host") == [f"demo.ckan.org:{CKAN_FRONT_IP}"]
    assert environment(args)["NODE_EXTRA_CA_CERTS"] == _AUTHORITY
    authority = stand_in_files("demo.ckan.org").authority
    assert mount_of(args, _AUTHORITY) == f"{authority}:{_AUTHORITY}:ro"
