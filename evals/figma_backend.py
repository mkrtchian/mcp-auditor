"""The Figma API responder backend's lifecycle.

A light TLS responder standing in for the REST host that the tools of the Figma MCP server call.
It serves a fixed benign body on `api.figma.com`. Like the Facebook Ads responder it is cheap to
stand and a singleton on a fixed address: stood once and reused across a server's concurrent
nuisance runs, reaped by the generic orphan sweep, so no lock is held across the yield. The
responder carries no witness: figma's fix-check plants its witness as a file the injected shell
command reads, so the one benign responder serves the run and the fix-check alike, on the bridge
and subnet exported here.

The audited server reaches the responder as an outbound HTTPS request, not over MCP stdio. The
host is DNS-aliased to it with `--add-host`, and the responder's cert is self-signed. The server is
Node and the command-injection flaw runs through a `curl` child process, so both runtimes must
trust the public cert baked into the image at `FIGMA_CA_BUNDLE`: `NODE_EXTRA_CA_CERTS` for the
`fetch`, `CURL_CA_BUNDLE` for the curl fallback child that the former does not reach. The server
exits at startup without a key, so `FIGMA_API_KEY` is set to a dummy. All of it is `docker run`
arguments of the server's own container (`figma_network_args`), not the auditor's `--env` flag.
`--stdio` is the server's own transport flag and rides in the server launch, not here. The
responder sits in the RFC 2544 benchmarking range on its own bridge: the flaw is hostname-based,
the range only has to differ from the other responders'.

A caller drives this through `ensure_figma_responder`, `figma_server_args`, `figma_rm` and
`FIGMA_LAUNCH_LOCK`, built on the shared lifecycle of `responder_backend`.
"""

import threading
from collections.abc import Sequence

from evals.cve_planting_base import PlantingHost
from evals.docker_paths import DOCKER_DIRECTORY
from evals.responder_backend import Responder, remove

FIGMA_RESPONDER_IMAGE = "mcp-auditor-cve-figma-responder:local"
FIGMA_RESPONDER_CONTAINER = "mcp-auditor-cve-figma-responder"
FIGMA_RESPONDER_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.figma-responder"
FIGMA_BRIDGE = "mcp-auditor-cve-figma-bridge"  # server <-> responder, static IPs
FIGMA_SUBNET = "198.18.6.0/24"  # RFC 2544: overlaps no other responder's subnet
FIGMA_RESPONDER_IP = "198.18.6.2"
FIGMA_BENIGN_HOST = "api.figma.com"
FIGMA_CA_BUNDLE = "/ca.pem"

# The responder is a singleton on a fixed IP, so a caller does not hold this across its yield: a
# server's concurrent runs share the one responder. A plain Lock serialises only the stand-up,
# since __enter__ and __exit__ may run on different worker threads.
FIGMA_LAUNCH_LOCK = threading.Lock()

_RESPONDER = Responder(
    image=FIGMA_RESPONDER_IMAGE,
    container=FIGMA_RESPONDER_CONTAINER,
    bridge=FIGMA_BRIDGE,
    subnet=FIGMA_SUBNET,
    ip=FIGMA_RESPONDER_IP,
    dockerfile=FIGMA_RESPONDER_DOCKERFILE,
)


def figma_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    extra = figma_network_args(FIGMA_RESPONDER_IP)
    return _RESPONDER.server_args(name, image, host, server_launch, extra)


def figma_network_args(responder_address: str) -> list[str]:
    return [
        "--add-host",
        f"{FIGMA_BENIGN_HOST}:{responder_address}",
        "-e",
        f"NODE_EXTRA_CA_CERTS={FIGMA_CA_BUNDLE}",
        "-e",
        f"CURL_CA_BUNDLE={FIGMA_CA_BUNDLE}",
        "-e",
        "FIGMA_API_KEY=dummy",
    ]


def ensure_figma_responder() -> None:
    _RESPONDER.ensure()


def figma_rm(name: str) -> None:
    remove(name)
