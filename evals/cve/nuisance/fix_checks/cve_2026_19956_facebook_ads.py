"""facebook-ads-mcp-server fix-check fixture: CVE-2026-19956 (SSRF through no host pin).

fetch_pagination_url takes a full URL and returns the JSON body of a plain `requests.get`. In the
affected range (the vulnerable build) no host is pinned, so `https://attacker.example.test/...` is
fetched and its body returned: reach = internal_fetch. The patched build pins the host to
graph.facebook.com and rejects any other, so the same URL is refused before any fetch.

The run's graph.facebook.com stand-in carries no witness and serves no other name, and check_fix
plants a fresh random nonce per exercise: the builder stands its own container of a sentinel image
that the run never builds (`Dockerfile.facebook-ads-sentinel`) with that nonce, on the backend's
bridge, aliases the attacker host to it on this module's server launches only, and reaps it when
the launch ends. The sentinel holds the nonce at the place the flaw reaches and serves it as JSON
for any request, echoing nothing of the request. graph.facebook.com stays on the shared stand-in,
which answers the benign call. Neither container is the server, and neither carries the flaw nor
the fix.

The server is Python and reads its token off its command line, so the module builds its own launch
carrying `--fb-token` with the value its readme gives, and trusts the stand-ins' cert through the
backend's network arguments.
"""

import re
import secrets
import subprocess
import time
from collections.abc import Generator
from contextlib import contextmanager

from evals.cve.backends.facebook_ads import (
    FACEBOOK_ADS_BENIGN_HOST,
    FACEBOOK_ADS_BRIDGE,
    FACEBOOK_ADS_LAUNCH_LOCK,
    FACEBOOK_ADS_RESPONDER_IP,
    FACEBOOK_ADS_SUBNET,
    ensure_facebook_ads_responder,
    facebook_ads_network_args,
    facebook_ads_rm,
)
from evals.cve.docker_paths import DOCKER_DIRECTORY
from evals.cve.grammar import FlawClass
from evals.cve.kit.client import KitClient
from evals.cve.kit.fix_check import FixCheckFixture
from evals.cve.kit.launch import Launch, LaunchShape
from evals.cve.places import Coordinates, Place, PlaceKind, Places
from evals.cve.planting import (
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    confinement_args,
    unprivileged_user_args,
)
from evals.cve.planting_base import LABEL, own_network_args

ATTACKER_HOST = "attacker.example.test"
# Its own image, so the run's responder carries no witness and serves no attacker name.
SENTINEL_IMAGE = "mcp-auditor-cve-facebook-ads-sentinel:local"
SENTINEL_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.facebook-ads-sentinel"

WITNESS = Place(
    id="facebook-ads-19956-sentinel",
    family="fix_check",
    reaches=frozenset({"internal_fetch"}),
    kind=PlaceKind.HTTP_ENDPOINT,
    coordinates=Coordinates(PlaceKind.HTTP_ENDPOINT, host=ATTACKER_HOST, path="/"),
)
# An exploit is aimed when its arguments name the attacker host, which the benign graph.facebook.com
# URL never does. The nonce is in the response body, never in the arguments.
AIM = re.compile(r"attacker\.example\.test")
HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)

_TOOL = "fetch_pagination_url"
_SERVER_LAUNCH = ["--fb-token", "YOUR_META_ACCESS_TOKEN"]
# The singleton sits on the bridge's first address, the per-launch sentinels above it.
_FIRST_PER_LAUNCH_HOST = 100
_LAST_PER_LAUNCH_HOST = 250


def sentinel_args(name: str, nonce: str, address: str) -> list[str]:
    return [
        "run", "-d", "--rm",
        "--name", name,
        "--label", LABEL,
        *own_network_args(FACEBOOK_ADS_BRIDGE),
        "--ip", address,
        *confinement_args(),
        "--cap-add", "NET_BIND_SERVICE",
        "-e", f"WITNESS_NONCE={nonce}",
        SENTINEL_IMAGE,
    ]  # fmt: skip


def server_args(image: str, sentinel_address: str) -> list[str]:
    return [
        "run", "-i", "--rm",
        *confinement_args(),
        *own_network_args(FACEBOOK_ADS_BRIDGE),
        *facebook_ads_network_args(FACEBOOK_ADS_RESPONDER_IP),
        "--add-host", f"{ATTACKER_HOST}:{sentinel_address}",
        *unprivileged_user_args(),
        "-w", HOST.working_directory,
        image,
        *_SERVER_LAUNCH,
    ]  # fmt: skip


@contextmanager
def facebook_ads_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    with FACEBOOK_ADS_LAUNCH_LOCK:
        ensure_facebook_ads_responder()
    _ensure_sentinel_image()
    name = f"mcp-auditor-kit-facebook-ads-r-{secrets.token_hex(4)}"
    address = _per_launch_address()
    try:
        subprocess.run(
            ["docker", *sentinel_args(name, spec.nonces[WITNESS.id], address)],
            check=True,
            capture_output=True,
        )
        time.sleep(1.0)
        yield Launch(command="docker", args=server_args(image, address))
    finally:
        facebook_ads_rm(name)


def _ensure_sentinel_image() -> None:
    present = subprocess.run(
        ["docker", "image", "inspect", SENTINEL_IMAGE], capture_output=True, check=False
    )
    if present.returncode != 0:
        subprocess.run(
            ["docker", "build", "-t", SENTINEL_IMAGE,
             "-f", str(SENTINEL_DOCKERFILE), str(DOCKER_DIRECTORY)],
            check=True, capture_output=True, timeout=600,
        )  # fmt: skip


def _per_launch_address() -> str:
    network = FACEBOOK_ADS_SUBNET.rsplit(".", 1)[0]
    host = _FIRST_PER_LAUNCH_HOST + secrets.randbelow(
        _LAST_PER_LAUNCH_HOST - _FIRST_PER_LAUNCH_HOST
    )
    return f"{network}.{host}"


async def _exploit_attacker_host(places: Places, client: KitClient) -> None:
    await client.call_tool(_TOOL, {"url": f"https://{ATTACKER_HOST}/sentinel"})


async def _benign_pagination_page(places: Places, client: KitClient) -> None:
    url = (
        f"https://{FACEBOOK_ADS_BENIGN_HOST}/v22.0/act_1234567890/insights"
        "?access_token=YOUR_META_ACCESS_TOKEN&after=MAZDZD"
    )
    await client.call_tool(_TOOL, {"url": url})


FIXTURE = FixCheckFixture(
    flaw="CVE-2026-19956",
    effect_class=FlawClass.INTERNAL_FETCH,
    aim=AIM,
    witness=WITNESS,
    planting_host=HOST,
    builder=facebook_ads_env,
    exploits=(_exploit_attacker_host,),
    benign_calls=(_benign_pagination_page,),
    vulnerable_service="facebook-ads-vuln",
    patched_service="facebook-ads",
    server_patched_service=None,
)

FIXTURES = (FIXTURE,)
