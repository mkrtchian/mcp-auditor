"""The Apify documentation responder backend's lifecycle.

A light TLS responder standing in for the documentation host the `fetch-apify-docs` tool of
@apify/actors-mcp-server fetches from. It serves a fixed benign page on `docs.apify.com` and, on
the suffix host `docs.apify.com.<name>` that the vulnerable `startsWith` allowlist lets through,
a page carrying `WITNESS_NONCE` when it is set. Like the CKAN responder it is cheap to stand and
a singleton on a fixed address: stood once and reused across a server's concurrent nuisance
runs, reaped by the generic orphan sweep, so no lock is held across the yield. The singleton
carries no witness nonce, so it serves the run-phase benign call only: a fix-check stands its
own container of the same image with `WITNESS_NONCE` set, on the bridge and subnet exported here.

The audited server reaches the responder as an outbound HTTPS fetch, not over MCP stdio. Both
names are DNS-aliased to it with `--add-host`, and the responder's cert is self-signed, so the
server runs with `NODE_TLS_REJECT_UNAUTHORIZED=0`. Both are `docker run` arguments of the
server's own container (`apify_network_args`, which also carries the dummy `APIFY_TOKEN` the
server refuses to start without), not the auditor's `--env` flag. The responder
sits in the RFC 2544 benchmarking range on its own bridge: the allowlist is hostname-based, the
range only has to differ from the other responders'.

A caller drives this through `ensure_apify_responder`, `apify_server_args`, `apify_rm` and
`APIFY_LAUNCH_LOCK`, built on the shared lifecycle of `responder_backend`.
"""

import threading
from collections.abc import Sequence

from evals.cve_planting_base import PlantingHost
from evals.cve_targets import DOCKER_DIRECTORY
from evals.responder_backend import Responder, remove

APIFY_RESPONDER_IMAGE = "mcp-auditor-cve-apify-responder:local"
APIFY_RESPONDER_CONTAINER = "mcp-auditor-cve-apify-responder"
APIFY_RESPONDER_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.apify-responder"
APIFY_BRIDGE = "mcp-auditor-cve-apify-bridge"  # server <-> responder, static IPs
APIFY_SUBNET = "198.18.1.0/24"  # RFC 2544: overlaps no other responder's subnet
APIFY_RESPONDER_IP = "198.18.1.2"
APIFY_BENIGN_HOST = "docs.apify.com"
APIFY_SUFFIX_HOST = f"{APIFY_BENIGN_HOST}.example.test"

# The responder is a singleton on a fixed IP, so a caller does not hold this across its yield: a
# server's concurrent runs share the one responder. A plain Lock serialises only the stand-up,
# since __enter__ and __exit__ may run on different worker threads.
APIFY_LAUNCH_LOCK = threading.Lock()

_RESPONDER = Responder(
    image=APIFY_RESPONDER_IMAGE,
    container=APIFY_RESPONDER_CONTAINER,
    bridge=APIFY_BRIDGE,
    subnet=APIFY_SUBNET,
    ip=APIFY_RESPONDER_IP,
    dockerfile=APIFY_RESPONDER_DOCKERFILE,
)


def apify_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    extra = apify_network_args(APIFY_RESPONDER_IP)
    return _RESPONDER.server_args(name, image, host, server_launch, extra)


def apify_network_args(responder_address: str) -> list[str]:
    args: list[str] = []
    for host in (APIFY_BENIGN_HOST, APIFY_SUFFIX_HOST):
        args += ["--add-host", f"{host}:{responder_address}"]
    return [*args, "-e", "NODE_TLS_REJECT_UNAUTHORIZED=0", "-e", "APIFY_TOKEN=calib-token"]


def ensure_apify_responder() -> None:
    _RESPONDER.ensure()


def apify_rm(name: str) -> None:
    remove(name)
