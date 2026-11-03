"""The Jenkins responder backend's lifecycle.

A light HTTP responder standing in for the Jenkins controller that the tools of
hekmon8/Jenkins-server-mcp (`get_build_log`, `get_build_status`, `trigger_build`) call through
`JENKINS_URL`. It answers the legitimate build endpoints with a fixed benign body. Like the CKAN
responder it is cheap to stand and a singleton on a fixed address: stood once and reused across a
server's concurrent nuisance runs, reaped by the generic orphan sweep, so no lock is held across
the yield. The singleton carries no witness nonce, so it has no sentinel route and serves the
run-phase benign calls only: a fix-check stands its own container of the same image with
`WITNESS_NONCE` set, which adds the sentinel route, on the bridge and subnet exported here.

The audited server reaches the responder as an outbound HTTP request to a bare URL. Its
`JENKINS_URL`, `JENKINS_USER` and `JENKINS_TOKEN` are baked into the run image's own `ENV` at
`JENKINS_RESPONDER_IP`, so `jenkins_server_args` carries no `-e` of its own. A fix-check that
stands its responder on another address of the bridge overrides `JENKINS_URL` with a `-e` on the
server's `docker run`, which wins over the baked `ENV`. The responder sits in the RFC 2544
benchmarking range on its own bridge, overlapping no other responder's subnet.

A caller drives this through `ensure_jenkins_responder`, `jenkins_server_args`, `jenkins_rm` and
`JENKINS_LAUNCH_LOCK`, built on the shared lifecycle of `responder_backend`.
"""

import threading
from collections.abc import Sequence

from evals.cve_planting_base import PlantingHost
from evals.docker_paths import DOCKER_DIRECTORY
from evals.responder_backend import Responder, remove

JENKINS_RESPONDER_IMAGE = "mcp-auditor-cve-jenkins-responder:local"
JENKINS_RESPONDER_CONTAINER = "mcp-auditor-cve-jenkins-responder"
JENKINS_RESPONDER_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.jenkins-responder"
JENKINS_BRIDGE = "mcp-auditor-cve-jenkins-bridge"  # server <-> responder, static IPs
JENKINS_SUBNET = "198.18.2.0/24"  # RFC 2544: overlaps no other responder's subnet
JENKINS_RESPONDER_IP = "198.18.2.2"

# The responder is a singleton on a fixed IP, so a caller does not hold this across its yield: a
# server's concurrent runs share the one responder. A plain Lock serialises only the stand-up,
# since __enter__ and __exit__ may run on different worker threads.
JENKINS_LAUNCH_LOCK = threading.Lock()

_RESPONDER = Responder(
    image=JENKINS_RESPONDER_IMAGE,
    container=JENKINS_RESPONDER_CONTAINER,
    bridge=JENKINS_BRIDGE,
    subnet=JENKINS_SUBNET,
    ip=JENKINS_RESPONDER_IP,
    dockerfile=JENKINS_RESPONDER_DOCKERFILE,
)


def jenkins_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return _RESPONDER.server_args(name, image, host, server_launch)


def ensure_jenkins_responder() -> None:
    _RESPONDER.ensure()


def jenkins_rm(name: str) -> None:
    remove(name)
