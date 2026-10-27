"""The CKAN API responder backend's lifecycle.

A light HTTP/HTTPS responder that answers CKAN success:true envelopes so a patched
@aborruso/ckan-mcp-server's benign tool calls answer without error. Unlike the Doris cluster it
is cheap to stand, but like it the responder is a singleton on a fixed address: stood once and
reused across a server's concurrent nuisance runs, reaped by the generic orphan sweep, so no
lock is held across the yield.

The audited server reaches the responder as an outbound CKAN API, not over MCP stdio. The
patched server resolves each request host and rejects a private / link-local address, so the
responder sits at a public-range (TEST-NET-3) static IP on its own bridge and the dati.gov.it /
data.europa.eu hosts are DNS-aliased to it with `--add-host`. HTTPS is self-signed and the
server runs with `NODE_TLS_REJECT_UNAUTHORIZED=0`, because the CKAN portal rewrite forces the
dati.gov.it base URL to https and the MQA URLs are hardcoded https.

A caller drives this through `ensure_ckan_responder`, `ckan_server_args`, `ckan_rm` and
`CKAN_LAUNCH_LOCK`, built on the shared lifecycle of `responder_backend`.
"""

import threading
from collections.abc import Sequence

from evals.cve_planting_base import PlantingHost
from evals.cve_targets import DOCKER_DIRECTORY
from evals.responder_backend import Responder, remove

CKAN_RESPONDER_IMAGE = "mcp-auditor-cve-ckan-responder:local"
CKAN_RESPONDER_CONTAINER = "mcp-auditor-cve-ckan-responder"
CKAN_BRIDGE = "mcp-auditor-cve-ckan-bridge"  # server <-> responder, static public-range IPs
_CKAN_SUBNET = "203.0.113.0/24"  # TEST-NET-3: public-looking, so the patched SSRF guard passes
CKAN_RESPONDER_IP = "203.0.113.2"
# The hosts the audited server resolves to the responder: the dati.gov.it portal the CKAN tools
# and the MQA server_url target, and the data.europa.eu endpoint the MQA cache/metrics fetch hits.
CKAN_ALIASES: tuple[str, ...] = ("www.dati.gov.it", "dati.gov.it", "data.europa.eu")

# The responder is a singleton on a fixed IP, so a caller does not hold this across its yield: a
# server's concurrent runs share the one responder. A plain Lock, like DORIS_LAUNCH_LOCK, serialises
# only the stand-up, since __enter__ and __exit__ may run on different worker threads.
CKAN_LAUNCH_LOCK = threading.Lock()

_RESPONDER = Responder(
    image=CKAN_RESPONDER_IMAGE,
    container=CKAN_RESPONDER_CONTAINER,
    bridge=CKAN_BRIDGE,
    subnet=_CKAN_SUBNET,
    ip=CKAN_RESPONDER_IP,
    dockerfile=DOCKER_DIRECTORY / "Dockerfile.ckan-responder",
)


def ckan_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    extra = [*_alias_args(), "-e", "NODE_TLS_REJECT_UNAUTHORIZED=0"]
    return _RESPONDER.server_args(name, image, host, server_launch, extra)


def _alias_args() -> list[str]:
    args: list[str] = []
    for host in CKAN_ALIASES:
        args += ["--add-host", f"{host}:{CKAN_RESPONDER_IP}"]
    return args


def ensure_ckan_responder() -> None:
    _RESPONDER.ensure()


def ckan_rm(name: str) -> None:
    remove(name)
