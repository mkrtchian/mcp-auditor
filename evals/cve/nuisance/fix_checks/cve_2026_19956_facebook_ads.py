"""facebook-ads-mcp-server fix-check fixture: CVE-2026-19956 (SSRF through no host pin).

fetch_pagination_url takes a full URL and returns the JSON body of a plain `requests.get`. In the
affected range (the vulnerable build) no host is pinned, so `https://attacker.example.test/...` is
fetched and its body returned: reach = internal_fetch. The patched build pins the host to
graph.facebook.com and rejects any other, so the same URL is refused before any fetch.

The run's graph.facebook.com stand-in carries no witness and serves no other name, and check_fix
plants a fresh random witness per exercise: the builder stands its own container of a sentinel
image that the run never builds (`Dockerfile.facebook-ads-sentinel`) with that witness, on the
backend's bridge, aliases the attacker host to it on this module's server launches only, and reaps
it when the launch ends. The sentinel holds the witness at the place the flaw reaches and serves it
as JSON for any request, echoing nothing of the request. graph.facebook.com stays on the shared
stand-in, which answers the benign call. Neither container is the server, and neither carries the
flaw nor the fix.

The sentinel serves a certificate of its own, generated when its image is built and naming the
attacker host only, outside the fixture authority, so nothing a run builds or serves carries that
name. The builder reads it from the built image, writes a bundle of the fixture authority and that
certificate, and mounts it on this module's launch alone, where `REQUESTS_CA_BUNDLE` points at it
in place of the run's authority. The server is Python and reads its token off its command line,
so the module builds its own launch carrying `--fb-token` with the value its readme gives.
"""

import re
import secrets
import shutil
import subprocess
import tempfile
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from evals.cve.backends.facebook_ads import (
    FACEBOOK_ADS_BENIGN_HOST,
    FACEBOOK_ADS_BRIDGE,
    FACEBOOK_ADS_LAUNCH_LOCK,
    FACEBOOK_ADS_RESPONDER_IP,
    FACEBOOK_ADS_SUBNET,
    ensure_facebook_ads_responder,
    facebook_ads_graph_host_args,
    facebook_ads_rm,
    facebook_ads_trust_args,
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
from evals.cve.public_stand_ins import stand_in_files

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
# URL never does. The witness is in the response body, never in the arguments.
AIM = re.compile(r"attacker\.example\.test")
HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)

_TOOL = "fetch_pagination_url"
_SERVER_LAUNCH = ["--fb-token", "YOUR_META_ACCESS_TOKEN"]
# The singleton sits on the bridge's first address, the per-launch sentinels above it.
_FIRST_PER_LAUNCH_HOST = 100
_LAST_PER_LAUNCH_HOST = 250


@contextmanager
def facebook_ads_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    with FACEBOOK_ADS_LAUNCH_LOCK:
        ensure_facebook_ads_responder()
    _ensure_sentinel_image()
    name = f"mcp-auditor-kit-facebook-ads-r-{secrets.token_hex(4)}"
    address = _per_launch_address()
    directory = Path(tempfile.mkdtemp(prefix="facebook-ads-trust-"))
    try:
        bundle = write_trust_bundle(directory, _sentinel_certificate())
        subprocess.run(
            ["docker", *sentinel_args(name, spec.nonces[WITNESS.id], address)],
            check=True,
            capture_output=True,
        )
        time.sleep(1.0)
        yield Launch(command="docker", args=server_args(image, address, bundle))
    finally:
        facebook_ads_rm(name)
        shutil.rmtree(directory, ignore_errors=True)


def sentinel_args(name: str, witness: str, address: str) -> list[str]:
    return [
        "run", "-d", "--rm",
        "--name", name,
        "--label", LABEL,
        *own_network_args(FACEBOOK_ADS_BRIDGE),
        "--ip", address,
        *confinement_args(),
        "--cap-add", "NET_BIND_SERVICE",
        "-e", f"WITNESS_NONCE={witness}",
        SENTINEL_IMAGE,
    ]  # fmt: skip


def server_args(image: str, sentinel_address: str, trust_bundle: Path) -> list[str]:
    return [
        "run", "-i", "--rm",
        *confinement_args(),
        *own_network_args(FACEBOOK_ADS_BRIDGE),
        *facebook_ads_graph_host_args(FACEBOOK_ADS_RESPONDER_IP),
        "--add-host", f"{ATTACKER_HOST}:{sentinel_address}",
        *facebook_ads_trust_args(trust_bundle),
        *unprivileged_user_args(),
        "-w", HOST.working_directory,
        image,
        *_SERVER_LAUNCH,
    ]  # fmt: skip


def write_trust_bundle(directory: Path, sentinel_certificate: str) -> Path:
    bundle = directory / "trust-bundle.pem"
    authority = stand_in_files(FACEBOOK_ADS_BENIGN_HOST).authority.read_text()
    bundle.write_text(authority + sentinel_certificate)
    bundle.chmod(0o644)  # read by the server's unprivileged account through the mount
    return bundle


def _sentinel_certificate() -> str:
    return subprocess.run(
        ["docker", "run", "--rm", "--label", LABEL, "--network", "none",
         "--entrypoint", "cat", SENTINEL_IMAGE, "/cert.pem"],
        check=True, capture_output=True, text=True, timeout=120,
    ).stdout  # fmt: skip


def _ensure_sentinel_image() -> None:
    # Built every time, from the layer cache once built, so a changed Dockerfile is never stale.
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
