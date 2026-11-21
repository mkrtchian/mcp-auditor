from collections.abc import Sequence

from evals.cve.backends.httpbin import HTTPBIN_BRIDGE
from evals.cve.planting_base import confinement_args
from evals.cve.public_stand_ins import stand_in_files
from tests.unit.support.docker_argv import (
    carries,
    count,
    environment,
    mount_of,
    value_after,
    values_after,
)

_FILES = stand_in_files("httpbin.org")


def joins_the_bridge_with_httpbin_org_at_the_front(server_args: Sequence[str]) -> None:
    assert value_after(server_args, "--network") == HTTPBIN_BRIDGE
    assert carries(server_args, ["--add-host", "httpbin.org:44.209.237.184"])
    assert carries(server_args, confinement_args())


def trusts_the_fixture_authority_through_ssl_cert_file(server_args: Sequence[str]) -> None:
    bundle = environment(server_args)["SSL_CERT_FILE"]
    assert mount_of(server_args, bundle) == f"{_FILES.authority}:{bundle}:ro"


def mounts_the_leaf_and_key_of_httpbin_org(front_args: Sequence[str]) -> None:
    mounts = {mount.split(":")[0]: mount for mount in values_after(front_args, "-v")}
    assert mounts[str(_FILES.certificate)].endswith(":ro")
    assert mounts[str(_FILES.key)].endswith(":ro")


def carries_the_hardening_with_no_capability(part_args: Sequence[str]) -> None:
    assert carries(part_args, ["--cap-drop", "ALL"])
    assert carries(part_args, ["--security-opt", "no-new-privileges"])
    assert int(value_after(part_args, "--pids-limit")) > 0
    assert carries(part_args, ["--memory", "4g", "--memory-swap", "4g"])
    assert count(part_args, ["--cap-add"]) == 0


def sits_on_the_bridge_at_its_address(part_args: Sequence[str], ip: str) -> None:
    assert value_after(part_args, "--network") == HTTPBIN_BRIDGE
    assert value_after(part_args, "--ip") == ip
