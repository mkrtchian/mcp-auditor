"""The n8n REST responder backend's lifecycle.

A light HTTP responder standing in for the external n8n instance a patched n8n-mcp deployment
points `N8N_API_URL` at, so the patched server's benign workflow trigger answers without error.
Like the CKAN and ContextForge responders it is cheap to stand and a singleton on a fixed address:
stood once and reused across a server's concurrent nuisance runs, reaped by the generic orphan
sweep, so no lock is held across the yield.

The audited server reaches the responder as an outbound REST fetch, not over MCP stdio. The
responder sits at a public-range (TEST-NET-1) static IP on its own bridge, and the run image bakes
`N8N_API_URL`, `N8N_API_KEY` and `N8N_MCP_TELEMETRY_DISABLED` into its `ENV`, so the lifecycle
passes no environment of its own.

A caller drives this through `ensure_n8n_responder`, `n8n_server_args`, `n8n_rm` and
`N8N_LAUNCH_LOCK`, built on the shared lifecycle of `responder_backend`.
"""

import threading
from collections.abc import Sequence

from evals.cve_planting_base import PlantingHost
from evals.cve_targets import DOCKER_DIRECTORY
from evals.responder_backend import Responder, remove

N8N_RESPONDER_IMAGE = "mcp-auditor-cve-n8n-responder:local"
N8N_RESPONDER_CONTAINER = "mcp-auditor-cve-n8n-responder"
N8N_BRIDGE = "mcp-auditor-cve-n8n-bridge"  # server <-> responder, static IPs
_N8N_SUBNET = "192.0.2.0/24"  # TEST-NET-1: overlaps neither the CKAN nor the ContextForge subnet
N8N_RESPONDER_IP = "192.0.2.2"  # the N8N_API_URL host

# The responder is a singleton on a fixed IP, so a caller does not hold this across its yield: a
# server's concurrent runs share the one responder. A plain Lock serialises only the stand-up,
# since __enter__ and __exit__ may run on different worker threads.
N8N_LAUNCH_LOCK = threading.Lock()

_RESPONDER = Responder(
    image=N8N_RESPONDER_IMAGE,
    container=N8N_RESPONDER_CONTAINER,
    bridge=N8N_BRIDGE,
    subnet=_N8N_SUBNET,
    ip=N8N_RESPONDER_IP,
    dockerfile=DOCKER_DIRECTORY / "Dockerfile.n8n-responder",
)


def n8n_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return _RESPONDER.server_args(name, image, host, server_launch)


def ensure_n8n_responder() -> None:
    _RESPONDER.ensure()


def n8n_rm(name: str) -> None:
    remove(name)
