"""The ContextForge REST responder backend's lifecycle.

A light HTTP responder that answers a benign body so a patched IBM ContextForge MCP Gateway's
benign REST tool call answers without error. Like the CKAN responder it is cheap to stand and a
singleton on a fixed address: stood once and reused across a server's concurrent nuisance runs,
reaped by the generic orphan sweep, so no lock is held across the yield.

The audited gateway reaches the responder as an outbound REST fetch, not over MCP stdio. The
patched 1.0.7 gateway re-resolves and pins the REST tool's host at invocation and rejects a private
/ link-local address, so the responder sits at a public-range (TEST-NET-2) static IP on its own
bridge and the benign REST tool points straight at that IP.

A caller drives this through `ensure_contextforge_responder`, `contextforge_server_args`,
`contextforge_rm` and `CONTEXTFORGE_LAUNCH_LOCK`, built on the shared lifecycle of
`responder_backend`.
"""

import threading
from collections.abc import Sequence

from evals.cve_planting_base import PlantingHost
from evals.cve_targets import DOCKER_DIRECTORY
from evals.responder_backend import Responder, remove

CONTEXTFORGE_RESPONDER_IMAGE = "mcp-auditor-cve-contextforge-responder:local"
CONTEXTFORGE_RESPONDER_CONTAINER = "mcp-auditor-cve-contextforge-responder"
CONTEXTFORGE_BRIDGE = "mcp-auditor-cve-contextforge-bridge"  # gateway <-> responder, static IPs
_CONTEXTFORGE_SUBNET = "198.51.100.0/24"  # TEST-NET-2: public-looking, so the SSRF guard passes
CONTEXTFORGE_RESPONDER_IP = "198.51.100.2"  # the benign REST tool's target

# The responder is a singleton on a fixed IP, so a caller does not hold this across its yield: a
# server's concurrent runs share the one responder. A plain Lock serialises only the stand-up,
# since __enter__ and __exit__ may run on different worker threads.
CONTEXTFORGE_LAUNCH_LOCK = threading.Lock()

_RESPONDER = Responder(
    image=CONTEXTFORGE_RESPONDER_IMAGE,
    container=CONTEXTFORGE_RESPONDER_CONTAINER,
    bridge=CONTEXTFORGE_BRIDGE,
    subnet=_CONTEXTFORGE_SUBNET,
    ip=CONTEXTFORGE_RESPONDER_IP,
    dockerfile=DOCKER_DIRECTORY / "Dockerfile.contextforge-responder",
)


def contextforge_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return _RESPONDER.server_args(name, image, host, server_launch)


def ensure_contextforge_responder() -> None:
    _RESPONDER.ensure()


def contextforge_rm(name: str) -> None:
    remove(name)
