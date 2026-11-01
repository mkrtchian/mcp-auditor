"""The Facebook Ads Graph API responder backend's lifecycle.

A light TLS responder standing in for the Graph API host that the tools of
gomarble-ai/facebook-ads-mcp-server call. It serves a fixed benign body on `graph.facebook.com`
and, on the out-of-host target `attacker.example.test` that the vulnerable server follows when a
tool argument carries a full URL, a body carrying `WITNESS_NONCE` when it is set. Like the
Apify responder it is cheap to stand and a singleton on a fixed address: stood once and reused
across a server's concurrent nuisance runs, reaped by the generic orphan sweep, so no lock is held
across the yield. The singleton carries no witness nonce, so it serves the run-phase benign call
only: a fix-check stands its own container of the same image with `WITNESS_NONCE` set, on the
bridge and subnet exported here.

The audited server reaches the responder as an outbound HTTPS request, not over MCP stdio. Both
names are DNS-aliased to it with `--add-host`, and the responder's cert is self-signed. The
server is Python, so it trusts the public cert baked into its image at `FACEBOOK_ADS_CA_BUNDLE`
through `REQUESTS_CA_BUNDLE`, where the Node servers disable verification. Both are `docker run`
arguments of the server's own container (`facebook_ads_network_args`), not the auditor's `--env`
flag. The server reads its token off its command line (`--fb-token`), so the token rides in the
server launch and the network arguments carry none. The responder sits in the RFC 2544
benchmarking range on its own bridge: the SSRF is hostname-based, the range only has to differ
from the other responders'.

A caller drives this through `ensure_facebook_ads_responder`, `facebook_ads_server_args`,
`facebook_ads_rm` and `FACEBOOK_ADS_LAUNCH_LOCK`, built on the shared lifecycle of
`responder_backend`.
"""

import threading
from collections.abc import Sequence

from evals.cve_planting_base import PlantingHost
from evals.cve_targets import DOCKER_DIRECTORY
from evals.responder_backend import Responder, remove

FACEBOOK_ADS_RESPONDER_IMAGE = "mcp-auditor-cve-facebook-ads-responder:local"
FACEBOOK_ADS_RESPONDER_CONTAINER = "mcp-auditor-cve-facebook-ads-responder"
FACEBOOK_ADS_RESPONDER_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.facebook-ads-responder"
FACEBOOK_ADS_BRIDGE = "mcp-auditor-cve-facebook-ads-bridge"  # server <-> responder, static IPs
FACEBOOK_ADS_SUBNET = "198.18.5.0/24"  # RFC 2544: overlaps no other responder's subnet
FACEBOOK_ADS_RESPONDER_IP = "198.18.5.2"
FACEBOOK_ADS_BENIGN_HOST = "graph.facebook.com"
FACEBOOK_ADS_ATTACKER_HOST = "attacker.example.test"
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
    args: list[str] = []
    for host in (FACEBOOK_ADS_BENIGN_HOST, FACEBOOK_ADS_ATTACKER_HOST):
        args += ["--add-host", f"{host}:{responder_address}"]
    return [*args, "-e", f"REQUESTS_CA_BUNDLE={FACEBOOK_ADS_CA_BUNDLE}"]


def ensure_facebook_ads_responder() -> None:
    _RESPONDER.ensure()


def facebook_ads_rm(name: str) -> None:
    remove(name)
