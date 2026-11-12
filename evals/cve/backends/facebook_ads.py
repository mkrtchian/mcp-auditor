"""The Facebook Ads Graph API stand-in backend's lifecycle.

A light TLS responder standing in for `graph.facebook.com`, the Graph API host the tools of
gomarble-ai/facebook-ads-mcp-server call (a remote Meta service behind an account and a token).
It answers the insights edge with the first example response of Meta's Ads Insights API page
(extracted block sha256 4aa6b9ffc52591722ca701686facef70d604f8428a7fd0c8bab7ec8d3f53ab72) and any
other request with the real Graph API's captured errors (`Dockerfile.facebook-ads-responder`). It
is cheap to stand and a singleton on a fixed address: stood once and reused across a server's
concurrent nuisance runs, reaped by the generic orphan sweep, so no lock is held across the yield.
It carries no witness and serves no other name. The fix check of CVE-2026-19956 stands a sentinel
of its own on the bridge and subnet exported here.

The audited server reaches the responder as an outbound HTTPS request, not over MCP stdio.
`graph.facebook.com` is DNS-aliased to it with `--add-host`, and the responder's cert is
self-signed. The server is Python, so it trusts the public cert baked into its image at
`FACEBOOK_ADS_CA_BUNDLE` through `REQUESTS_CA_BUNDLE`. Both are `docker run` arguments of the
server's own container (`facebook_ads_network_args`). The server reads its token off its command
line (`--fb-token`), so the token rides in the server launch. The responder sits in the RFC 2544
benchmarking range on its own bridge, a range no other responder uses.

A caller drives this through `ensure_facebook_ads_responder`, `facebook_ads_server_args`,
`facebook_ads_rm` and `FACEBOOK_ADS_LAUNCH_LOCK`, built on the shared lifecycle of
`responder_backend`.
"""

import threading
from collections.abc import Sequence

from evals.cve.backends.lifecycle import BackendLifecycle
from evals.cve.backends.responder import Responder, remove
from evals.cve.docker_paths import DOCKER_DIRECTORY
from evals.cve.planting_base import PlantingHost

FACEBOOK_ADS_RESPONDER_IMAGE = "mcp-auditor-cve-facebook-ads-responder:local"
FACEBOOK_ADS_RESPONDER_CONTAINER = "mcp-auditor-cve-facebook-ads-responder"
FACEBOOK_ADS_RESPONDER_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.facebook-ads-responder"
FACEBOOK_ADS_BRIDGE = "mcp-auditor-cve-facebook-ads-bridge"  # server <-> responder, static IPs
FACEBOOK_ADS_SUBNET = "198.18.5.0/24"  # RFC 2544: overlaps no other responder's subnet
FACEBOOK_ADS_RESPONDER_IP = "198.18.5.2"
FACEBOOK_ADS_BENIGN_HOST = "graph.facebook.com"
FACEBOOK_ADS_CA_BUNDLE = "/ca.pem"

# The responder is a singleton on a fixed IP, so a caller does not hold this across its yield: a
# server's concurrent runs share the one responder. A plain Lock serialises only the stand-up,
# since __enter__ and __exit__ may run on different worker threads.
FACEBOOK_ADS_LAUNCH_LOCK = threading.Lock()

_RESPONDER = Responder(
    image=FACEBOOK_ADS_RESPONDER_IMAGE,
    container=FACEBOOK_ADS_RESPONDER_CONTAINER,
    bridge=FACEBOOK_ADS_BRIDGE,
    subnet=FACEBOOK_ADS_SUBNET,
    ip=FACEBOOK_ADS_RESPONDER_IP,
    dockerfile=FACEBOOK_ADS_RESPONDER_DOCKERFILE,
)


def facebook_ads_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    extra = facebook_ads_network_args(FACEBOOK_ADS_RESPONDER_IP)
    return _RESPONDER.server_args(name, image, host, server_launch, extra)


def facebook_ads_network_args(responder_address: str) -> list[str]:
    return [
        "--add-host", f"{FACEBOOK_ADS_BENIGN_HOST}:{responder_address}",
        "-e", f"REQUESTS_CA_BUNDLE={FACEBOOK_ADS_CA_BUNDLE}",
    ]  # fmt: skip


def ensure_facebook_ads_responder() -> None:
    _RESPONDER.ensure()


def facebook_ads_rm(name: str) -> None:
    remove(name)


LIFECYCLE = BackendLifecycle(
    "facebook_ads",
    FACEBOOK_ADS_LAUNCH_LOCK,
    ensure_facebook_ads_responder,
    facebook_ads_server_args,
    facebook_ads_rm,
)
