"""The GitLab responder, which serves the fix check of CVE-2026-61462 only.

A light HTTP responder standing in for the GitLab instance that the pipeline-job tools of the
audited server call through `GITLAB_API_URL`. It answers the job endpoints with GitLab's own
documented example responses and spec fixtures (see Dockerfile.gitlab-responder), and any other
request with GitLab's 404. It is cheap to stand and a singleton on a fixed address: stood once
and reused across concurrent launches, reaped by the generic orphan sweep, so no lock is held
across the yield. The singleton carries no witness nonce, so it has no route that serves a
witness: the fix check stands its own container of the same image with `WITNESS_NONCE` set,
which adds that route, on the bridge and subnet exported here, and overrides the server's
`GITLAB_API_URL` with a `-e`, which wins over the run image's baked `ENV`. The responder sits in
the RFC 2544 benchmarking range on its own bridge, overlapping no other responder's subnet.

The fix check drives this through `ensure_gitlab_responder`, `gitlab_rm` and `GITLAB_LAUNCH_LOCK`,
built on the shared lifecycle of `evals.cve.backends.responder`.
"""

import threading

from evals.cve.backends.responder import Responder, remove
from evals.cve.docker_paths import DOCKER_DIRECTORY

GITLAB_RESPONDER_IMAGE = "mcp-auditor-cve-gitlab-responder:local"
GITLAB_RESPONDER_CONTAINER = "mcp-auditor-cve-gitlab-responder"
GITLAB_RESPONDER_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.gitlab-responder"
GITLAB_BRIDGE = "mcp-auditor-cve-gitlab-bridge"  # server <-> responder, static IPs
GITLAB_SUBNET = "198.18.4.0/24"  # RFC 2544: overlaps no other responder's subnet
GITLAB_RESPONDER_IP = "198.18.4.2"
GITLAB_RESPONDER_ALIAS = "gitlab.example.com"  # the host of GITLAB_API_URL in the run image

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
    run_args=("--network-alias", GITLAB_RESPONDER_ALIAS),
)


def ensure_gitlab_responder() -> None:
    _RESPONDER.ensure()


def gitlab_rm(name: str) -> None:
    remove(name)
