from collections.abc import Sequence

from evals.cve.backends.httpbin import HTTPBIN_BRIDGE, HTTPBIN_FRONT_IP
from evals.cve.planting_base import confinement_args
from evals.cve.public_stand_ins import stand_in_files
from tests.unit.support.docker_argv import carries, value_after, values_after

_FILES = stand_in_files("httpbin.org")


def joins_the_bridge_with_httpbin_org_at_the_front(server_args: Sequence[str]) -> None:
    assert value_after(server_args, "--network") == HTTPBIN_BRIDGE
    assert carries(server_args, ["--add-host", f"httpbin.org:{HTTPBIN_FRONT_IP}"])
    assert carries(server_args, confinement_args())


def mounts_the_leaf_and_key_of_httpbin_org(front_args: Sequence[str]) -> None:
    mounts = {mount.split(":")[0]: mount for mount in values_after(front_args, "-v")}
    assert mounts[str(_FILES.certificate)].endswith(":ro")
    assert mounts[str(_FILES.key)].endswith(":ro")


def sits_on_the_bridge_at_its_address(part_args: Sequence[str], ip: str) -> None:
    assert value_after(part_args, "--network") == HTTPBIN_BRIDGE
    assert value_after(part_args, "--ip") == ip
