"""The Jira and Confluence responder backend's lifecycle.

A light HTTP responder standing in for the Atlassian Server/DC instance an mcp-atlassian
deployment points `JIRA_URL` and `CONFLUENCE_URL` at, serving a project and a space pair named
ALLOWED and SECRET. Like the CKAN responder it is cheap to stand and a singleton on a fixed
address: stood once and reused across a server's concurrent nuisance runs, reaped by the generic
orphan sweep, so no lock is held across the yield. The singleton carries no witness nonce, so it
serves the run-phase benign calls only: a fix-check stands its own container of the same image
with `WITNESS_NONCE` set, on the bridge and subnet exported here.

The audited server reaches the responder as an outbound REST API, not over MCP stdio. Its
configuration is `-e` arguments of the server's own `docker run` (`atlassian_env_args`), not the
auditor's `--env` flag. The responder sits in the RFC 2544 benchmarking range on its own bridge:
neither side has an IP-range guard, the range only has to differ from the other responders'.

A caller drives this through `ensure_atlassian_responder`, `atlassian_server_args`,
`atlassian_rm` and `ATLASSIAN_LAUNCH_LOCK`, built on the shared lifecycle of `responder_backend`.
"""

import threading
from collections.abc import Sequence

from evals.cve_planting_base import PlantingHost
from evals.docker_paths import DOCKER_DIRECTORY
from evals.responder_backend import Responder, remove

ATLASSIAN_RESPONDER_IMAGE = "mcp-auditor-cve-atlassian-responder:local"
ATLASSIAN_RESPONDER_CONTAINER = "mcp-auditor-cve-atlassian-responder"
ATLASSIAN_RESPONDER_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.atlassian-responder"
ATLASSIAN_BRIDGE = "mcp-auditor-cve-atlassian-bridge"  # server <-> responder, static IPs
ATLASSIAN_SUBNET = "198.18.0.0/24"  # RFC 2544: overlaps no other responder's subnet
ATLASSIAN_RESPONDER_IP = "198.18.0.2"

# The responder is a singleton on a fixed IP, so a caller does not hold this across its yield: a
# server's concurrent runs share the one responder. A plain Lock serialises only the stand-up,
# since __enter__ and __exit__ may run on different worker threads.
ATLASSIAN_LAUNCH_LOCK = threading.Lock()

_RESPONDER = Responder(
    image=ATLASSIAN_RESPONDER_IMAGE,
    container=ATLASSIAN_RESPONDER_CONTAINER,
    bridge=ATLASSIAN_BRIDGE,
    subnet=ATLASSIAN_SUBNET,
    ip=ATLASSIAN_RESPONDER_IP,
    dockerfile=ATLASSIAN_RESPONDER_DOCKERFILE,
)


def atlassian_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    extra = atlassian_env_args(ATLASSIAN_RESPONDER_IP)
    return _RESPONDER.server_args(name, image, host, server_launch, extra)


def atlassian_env_args(responder_address: str) -> list[str]:
    environment = {
        "JIRA_URL": f"http://{responder_address}",
        "CONFLUENCE_URL": f"http://{responder_address}",
        "JIRA_PERSONAL_TOKEN": "calib-token",
        "CONFLUENCE_PERSONAL_TOKEN": "calib-token",
        "JIRA_PROJECTS_FILTER": "ALLOWED",
        "CONFLUENCE_SPACES_FILTER": "ALLOWED",
    }
    return [argument for pair in environment.items() for argument in ("-e", "=".join(pair))]


def ensure_atlassian_responder() -> None:
    _RESPONDER.ensure()


def atlassian_rm(name: str) -> None:
    remove(name)
