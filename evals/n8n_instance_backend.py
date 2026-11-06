"""The real n8n instance GHSA-8g7g-hmwm-6rv2's server points `N8N_API_URL` at, and its lifecycle.

n8n-mcp's API tools talk to an n8n instance, the workflow-automation software its documentation
names. Each planted launch starts the image n8n distributes inside the planting holder, on a
TEST-NET-3 address of the holder's loopback (`N8N_INSTANCE_IP`, which the server's webhook URL
validation treats as an ordinary public host), and provisions it through n8n's own REST and public
API: owner setup, an API key, and one active webhook workflow whose Respond to Webhook node answers
the webhook with a 302 to the request's `u` query parameter. The redirect target is therefore the
exploit call's own argument, and n8n never fetches it: the nonce surfaces only if the server follows
the 302.

`running_n8n_instance` stands the instance up, records the provisioned workflow's id for the
launch in progress (`provisioned_workflow_id`, which the target's exploits and benign call read,
since a call takes `(places, client)` and cannot see its launch) and removes the instance and the
record on exit. A target's checked launches never overlap, so one record suffices.

Unlike `n8n_backend` (the nuisance suite's REST responder), this module runs the real software.
"""

import json
import subprocess
from collections.abc import Generator
from contextlib import contextmanager
from uuid import uuid4

from evals.cve_planting import confinement_args
from evals.cve_planting_base import LABEL, SENTINEL_IMAGE

N8N_INSTANCE_IP = "203.0.113.10"  # TEST-NET-3 (RFC 5737)
N8N_PORT = 5678  # n8n's documented default listen port
N8N_API_URL = f"http://{N8N_INSTANCE_IP}:{N8N_PORT}/"
WEBHOOK_PATH = "relay"  # the path the provisioned workflow's webhook registers
_N8N_REDIRECT_IMAGE = "mcp-auditor-cve-holdout-ghsa-8g7g-hmwm-6rv2-n8n-redirect:local"

_provisioned: dict[str, str] = {}


def provisioned_workflow_id() -> str:
    return _provisioned["workflowId"]


@contextmanager
def running_n8n_instance(holder_ref: str) -> Generator[str]:
    """Start and provision the instance in the holder's namespace, yield its issued API key."""
    _bind_instance_address(holder_ref)
    instance = f"{LABEL}-n8n-{uuid4().hex}"
    try:
        _docker(
            "run", "-d", "--rm", "--label", LABEL, "--name", instance, *confinement_args(),
            "--network", holder_ref, _N8N_REDIRECT_IMAGE,
        )  # fmt: skip
        _provisioned.update(_provision(holder_ref))
        yield _provisioned["apiKey"]
    finally:
        _provisioned.clear()
        subprocess.run(["docker", "rm", "-f", instance], capture_output=True)


def _bind_instance_address(holder_ref: str) -> None:
    _docker(
        "run", "--rm", "--label", LABEL, *confinement_args(),
        "--cap-add", "NET_ADMIN", "--network", holder_ref,
        "--entrypoint", "ip", SENTINEL_IMAGE, "addr", "add", f"{N8N_INSTANCE_IP}/32", "dev", "lo",
    )  # fmt: skip


def _provision(holder_ref: str) -> dict[str, str]:
    # A helper container of the n8n image (for its node) joins the holder and reaches the instance
    # on loopback.
    output = _docker(
        "run", "--rm", "--label", LABEL, *confinement_args(), "--network", holder_ref,
        "--entrypoint", "node", _N8N_REDIRECT_IMAGE, "-e", _PROVISION_JS,
    )  # fmt: skip
    return json.loads(output.splitlines()[-1])


def _docker(*args: str) -> str:
    return subprocess.run(
        ["docker", *args], check=True, capture_output=True, text=True
    ).stdout.strip()


# Owner setup and the API key through n8n's REST, the workflow's creation and activation through its
# public API, then a wait until the webhook is registered. Node built-ins only.
_PROVISION_JS = r"""
const http = require('http');
const BASE = 'http://127.0.0.1:5678';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function req(method, path, opts) {
  opts = opts || {};
  return new Promise((resolve, reject) => {
    const data = opts.body ? JSON.stringify(opts.body) : null;
    const h = Object.assign({}, opts.headers || {});
    if (data) {
      h['Content-Type'] = 'application/json';
      h['Content-Length'] = Buffer.byteLength(data);
    }
    if (opts.jar && opts.jar.cookie) h['Cookie'] = opts.jar.cookie;
    const u = new URL(BASE + path);
    const r = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers: h },
      (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () => {
          if (opts.jar && res.headers['set-cookie'])
            opts.jar.cookie = res.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ');
          resolve({ status: res.statusCode, body });
        });
      }
    );
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}
async function waitReady(ms) {
  const t = Date.now();
  while (Date.now() - t < ms) {
    try {
      const s = await req('GET', '/rest/settings');
      if (s.status === 200 && s.body.indexOf('userManagement') !== -1) return;
    } catch (e) {}
    await sleep(1000);
  }
  throw new Error('n8n not ready');
}
async function main() {
  await waitReady(180000);
  const jar = {};
  const setup = await req('POST', '/rest/owner/setup', {
    jar,
    body: {
      email: 'ops@flow.example', firstName: 'Flow', lastName: 'Ops', password: 'Flowops2026',
    },
  });
  if (setup.status !== 200) throw new Error('owner setup ' + setup.status + ' ' + setup.body);
  const keyResp = await req('POST', '/rest/api-keys', {
    jar,
    body: {
      label: 'flow-ops',
      expiresAt: null,
      scopes: [
        'workflow:create', 'workflow:read', 'workflow:update', 'workflow:list',
        'workflow:activate',
      ],
    },
  });
  const apiKey = JSON.parse(keyResp.body).data.rawApiKey;
  const wf = {
    name: 'Inbound relay',
    nodes: [
      {
        parameters: { httpMethod: 'GET', path: 'relay', responseMode: 'responseNode', options: {} },
        id: 'a1', name: 'Webhook', type: 'n8n-nodes-base.webhook', typeVersion: 2,
        position: [0, 0], webhookId: 'relay',
      },
      {
        parameters: {
          respondWith: 'redirect', redirectURL: '={{ $json.query.u }}',
          options: { responseCode: 302 },
        },
        id: 'b2', name: 'Respond to Webhook', type: 'n8n-nodes-base.respondToWebhook',
        typeVersion: 1,
        position: [220, 0],
      },
    ],
    connections: { Webhook: { main: [[{ node: 'Respond to Webhook', type: 'main', index: 0 }]] } },
    settings: { executionOrder: 'v1' },
  };
  const create = await req('POST', '/api/v1/workflows', {
    headers: { 'X-N8N-API-KEY': apiKey }, body: wf,
  });
  const workflowId = JSON.parse(create.body).id;
  if (!workflowId) throw new Error('create workflow ' + create.status + ' ' + create.body);
  const act = await req('POST', '/api/v1/workflows/' + workflowId + '/activate', {
    headers: { 'X-N8N-API-KEY': apiKey },
  });
  if (act.status !== 200) throw new Error('activate ' + act.status + ' ' + act.body);
  const t = Date.now();
  let registered = false;
  while (Date.now() - t < 30000) {
    const w = await req('GET', '/webhook/relay');
    if (w.status !== 404) { registered = true; break; }
    await sleep(500);
  }
  if (!registered) throw new Error('webhook not registered');
  process.stdout.write(JSON.stringify({ apiKey, workflowId }) + '\n');
}
main().catch((e) => { console.error(e && e.message ? e.message : e); process.exit(1); });
"""
