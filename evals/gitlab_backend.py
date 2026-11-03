"""The GitLab responder backend's lifecycle.

A light HTTP responder standing in for the GitLab instance that the pipeline-job tools of the
audited server call through `GITLAB_API_URL`. It answers the legitimate API endpoints with a fixed
benign body. Like the Jenkins responder it is cheap to stand and a singleton on a fixed address:
stood once and reused across a server's concurrent nuisance runs, reaped by the generic orphan
sweep, so no lock is held across the yield. The singleton carries no witness nonce, so it has no
sentinel route and serves the run-phase benign calls only: a fix-check stands its own container
of the same image with `WITNESS_NONCE` set, which adds the sentinel route, on the bridge and subnet
exported here.

The audited server reaches the responder as an outbound HTTP request to a bare URL. Its
`GITLAB_API_URL` is baked into the run image's own `ENV` at `GITLAB_RESPONDER_IP`, so
`gitlab_server_args` carries no `-e` of its own. A fix-check that stands its responder on another
address of the bridge overrides `GITLAB_API_URL` with a `-e` on the server's `docker run`, which
wins over the baked `ENV`. The responder sits in the RFC 2544 benchmarking range on its own
bridge, overlapping no other responder's subnet.

A caller drives this through `ensure_gitlab_responder`, `gitlab_server_args`, `gitlab_rm` and
`GITLAB_LAUNCH_LOCK`, built on the shared lifecycle of `responder_backend`.
"""

import threading
from collections.abc import Sequence

from evals.cve_planting_base import PlantingHost
from evals.docker_paths import DOCKER_DIRECTORY
from evals.responder_backend import Responder, remove

GITLAB_RESPONDER_IMAGE = "mcp-auditor-cve-gitlab-responder:local"
GITLAB_RESPONDER_CONTAINER = "mcp-auditor-cve-gitlab-responder"
GITLAB_RESPONDER_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.gitlab-responder"
GITLAB_BRIDGE = "mcp-auditor-cve-gitlab-bridge"  # server <-> responder, static IPs
GITLAB_SUBNET = "198.18.4.0/24"  # RFC 2544: overlaps no other responder's subnet
GITLAB_RESPONDER_IP = "198.18.4.2"

# The responder is a singleton on a fixed IP, so a caller does not hold this across its yield: a
# server's concurrent runs share the one responder. A plain Lock serialises only the stand-up,
# since __enter__ and __exit__ may run on different worker threads.
GITLAB_LAUNCH_LOCK = threading.Lock()

_RESPONDER = Responder(
    image=GITLAB_RESPONDER_IMAGE,
    container=GITLAB_RESPONDER_CONTAINER,
    bridge=GITLAB_BRIDGE,
    subnet=GITLAB_SUBNET,
    ip=GITLAB_RESPONDER_IP,
    dockerfile=GITLAB_RESPONDER_DOCKERFILE,
)


def gitlab_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return _RESPONDER.server_args(name, image, host, server_launch)


def ensure_gitlab_responder() -> None:
    _RESPONDER.ensure()


def gitlab_rm(name: str) -> None:
    remove(name)
