"""googleapis/mcp-toolbox fix-check fixtures: CVE-2026-11720 and CVE-2026-14540.

Both flaws reach through the one HTTP tool `fetch_record`, whose path is
`/api/v1/users/{{.resource}}`. CVE-2026-11720 (read_outside_scope) is a base-path escape: on the
vulnerable build (1.2.0) the resource `../../../admin/secret` resolves out of `/api/v1/users/` to
`/admin/secret` on the upstream. CVE-2026-14540 (internal_fetch) is an off-origin redirect: the
upstream answers `/api/v1/users/redirect` with a 302 to an internal address, which the vulnerable
build follows. The patched build (1.10.0) rejects the dot segments and blocks the redirect to a
private address.

The shared singleton responder cannot carry the witness, since check_fix plants a fresh random
nonce per exercise: the builder stands its own responder of the same image with that nonce, and
reaps it when the launch ends. It serves the nonce on both witness routes and on the redirect's
`/sentinel`, and a benign body elsewhere. It is not the server and carries neither flaw nor fix.

The patched build only lets a request through to a public-range address, so the benign call needs
the responder on one, while the redirect has to land on a private one for the patched build to block
it. The responder and the server therefore both join two closed bridges (no route to the host or the
Internet), the backend's public one and a private one of this fixture, at the same per-launch host
number on each. The server's upstream is overridden to the public address with a `-e`, which wins
over the image's baked `ENV`.
"""

import re
import secrets
import subprocess
import time
from collections.abc import Generator
from contextlib import contextmanager

from evals.closed_network import ensure_closed_network
from evals.cve_grammar import MechanismClass
from evals.cve_places import Coordinates, Place, Places, PlantKind
from evals.cve_planting import (
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    confinement_args,
    unprivileged_user_args,
)
from evals.cve_planting_base import LABEL, own_network_args
from evals.googleapis_backend import (
    GOOGLEAPIS_BRIDGE,
    GOOGLEAPIS_LAUNCH_LOCK,
    GOOGLEAPIS_RESPONDER_IMAGE,
    GOOGLEAPIS_SUBNET,
    ensure_googleapis_responder,
    googleapis_rm,
)
from evals.holdout_kit.fix_check import FixCheckTarget
from evals.holdout_kit.kit_client import KitClient
from evals.holdout_kit.kit_launch import Launch, LaunchShape

INTERNAL_BRIDGE = "mcp-auditor-cve-googleapis-internal-bridge"
INTERNAL_SUBNET = "10.199.0.0/24"

WITNESS = Place(
    id="googleapis-witness",
    family="fix_check",
    reachable_by=frozenset({"read_outside_scope", "internal_fetch"}),
    kind=PlantKind.HTTP_ENDPOINT,
    coordinates=Coordinates(PlantKind.HTTP_ENDPOINT, host="googleapis-internal", path="/sentinel"),
)
HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)

_TOOL = "fetch_record"
EXPLOIT_BASE_PATH_ESCAPE = {"resource": "../../../admin/secret"}
EXPLOIT_REDIRECT = {"resource": "redirect"}
BENIGN_ARGUMENTS = {"resource": "1"}
_SERVER_LAUNCH: list[str] = []
# The singleton sits on the public bridge's first address, the per-launch responders above it.
_FIRST_PER_LAUNCH_HOST = 100
_LAST_PER_LAUNCH_HOST = 250


def responder_args(name: str, nonce: str, launch_host: int) -> list[str]:
    public_address = _address(GOOGLEAPIS_SUBNET, launch_host)
    return [
        "run", "-d", "--rm",
        "--name", name,
        "--label", LABEL,
        *own_network_args(f"name={GOOGLEAPIS_BRIDGE},ip={public_address}"),
        "--network", f"name={INTERNAL_BRIDGE},ip={_address(INTERNAL_SUBNET, launch_host)}",
        *confinement_args(),
        "--cap-add", "NET_BIND_SERVICE",
        "-e", f"WITNESS_NONCE={nonce}",
        "-e", f"REDIRECT_TARGET=http://{_address(INTERNAL_SUBNET, launch_host)}/sentinel",
        GOOGLEAPIS_RESPONDER_IMAGE,
    ]  # fmt: skip


def server_args(image: str, launch_host: int) -> list[str]:
    return [
        "run", "-i", "--rm",
        *confinement_args(),
        *own_network_args(GOOGLEAPIS_BRIDGE),
        "--network", INTERNAL_BRIDGE,
        "-e", f"UPSTREAM_URL=http://{_address(GOOGLEAPIS_SUBNET, launch_host)}",
        *unprivileged_user_args(),
        "-w", HOST.working_directory,
        image,
        *_SERVER_LAUNCH,
    ]  # fmt: skip


@contextmanager
def googleapis_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    with GOOGLEAPIS_LAUNCH_LOCK:
        ensure_googleapis_responder()
        ensure_closed_network(INTERNAL_BRIDGE, "--subnet", INTERNAL_SUBNET)
    name = f"mcp-auditor-kit-googleapis-r-{secrets.token_hex(4)}"
    launch_host = _per_launch_host()
    try:
        subprocess.run(
            ["docker", *responder_args(name, spec.nonces[WITNESS.id], launch_host)],
            check=True,
            capture_output=True,
        )
        time.sleep(1.0)
        yield Launch(command="docker", args=server_args(image, launch_host))
    finally:
        googleapis_rm(name)


def _per_launch_host() -> int:
    span = _LAST_PER_LAUNCH_HOST - _FIRST_PER_LAUNCH_HOST + 1
    return _FIRST_PER_LAUNCH_HOST + secrets.randbelow(span)


def _address(subnet: str, launch_host: int) -> str:
    return f"{subnet.rsplit('.', 1)[0]}.{launch_host}"


async def _exploit_base_path_escape(places: Places, client: KitClient) -> None:
    await client.call_tool(_TOOL, EXPLOIT_BASE_PATH_ESCAPE)


async def _exploit_redirect(places: Places, client: KitClient) -> None:
    await client.call_tool(_TOOL, EXPLOIT_REDIRECT)


async def _benign_fetch(places: Places, client: KitClient) -> None:
    await client.call_tool(_TOOL, BENIGN_ARGUMENTS)


TARGET_11720 = FixCheckTarget(
    flaw="CVE-2026-11720",
    mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
    aim=re.compile(r"\.\./|%2e%2e", re.I),
    witness=WITNESS,
    planting_host=HOST,
    builder=googleapis_env,
    exploits=(_exploit_base_path_escape,),
    benign_calls=(_benign_fetch,),
    vulnerable_service="googleapis-vuln",
    patched_service="googleapis",
    server_patched_service=None,
)

TARGET_14540 = FixCheckTarget(
    flaw="CVE-2026-14540",
    mechanism=MechanismClass.INTERNAL_FETCH,
    aim=re.compile(r"redirect", re.I),
    witness=WITNESS,
    planting_host=HOST,
    builder=googleapis_env,
    exploits=(_exploit_redirect,),
    benign_calls=(_benign_fetch,),
    vulnerable_service="googleapis-vuln",
    patched_service="googleapis",
    server_patched_service=None,
)

TARGETS = (TARGET_11720, TARGET_14540)
