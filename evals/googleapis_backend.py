"""The googleapis responder backend's lifecycle.

A light HTTP responder standing in for the Google API the HTTP tool of the googleapis server calls
through its base address. It serves the benign upstream only: a fixed JSON body on port 80 under the
tool's base path. Like the Jenkins responder it is cheap to stand and a singleton on a fixed
address: stood once and reused across a server's concurrent nuisance runs, reaped by the generic
orphan sweep, so no lock is held across the yield. The singleton carries no witness nonce, so it
serves the run-phase benign calls only: a fix-check stands its own witness container of the same
image on the bridge and subnet exported here.

The audited server reaches the responder as an outbound HTTP request to a bare URL. Its upstream
address is baked into the run image's own `ENV` at `GOOGLEAPIS_RESPONDER_IP`, so
`googleapis_server_args` carries no `-e` of its own. A fix-check that stands its responder on
another address of the bridge overrides it with a `-e` on the server's `docker run`, which wins over
the baked `ENV`. The responder sits in the RFC 2544 benchmarking range on its own bridge,
overlapping no other responder's subnet.

A caller drives this through `ensure_googleapis_responder`, `googleapis_server_args`,
`googleapis_rm` and `GOOGLEAPIS_LAUNCH_LOCK`, built on the shared lifecycle of `responder_backend`.
"""

import threading
from collections.abc import Sequence

from evals.cve_planting_base import PlantingHost
from evals.cve_targets import DOCKER_DIRECTORY
from evals.responder_backend import Responder, remove

GOOGLEAPIS_RESPONDER_IMAGE = "mcp-auditor-cve-googleapis-responder:local"
GOOGLEAPIS_RESPONDER_CONTAINER = "mcp-auditor-cve-googleapis-responder"
GOOGLEAPIS_RESPONDER_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.googleapis-responder"
GOOGLEAPIS_BRIDGE = "mcp-auditor-cve-googleapis-bridge"  # server <-> responder, static IPs
GOOGLEAPIS_SUBNET = "198.18.3.0/24"  # RFC 2544: overlaps no other responder's subnet
GOOGLEAPIS_RESPONDER_IP = "198.18.3.2"

# The responder is a singleton on a fixed IP, so a caller does not hold this across its yield: a
# server's concurrent runs share the one responder. A plain Lock serialises only the stand-up,
# since __enter__ and __exit__ may run on different worker threads.
GOOGLEAPIS_LAUNCH_LOCK = threading.Lock()

_RESPONDER = Responder(
    image=GOOGLEAPIS_RESPONDER_IMAGE,
    container=GOOGLEAPIS_RESPONDER_CONTAINER,
    bridge=GOOGLEAPIS_BRIDGE,
    subnet=GOOGLEAPIS_SUBNET,
    ip=GOOGLEAPIS_RESPONDER_IP,
    dockerfile=GOOGLEAPIS_RESPONDER_DOCKERFILE,
)


def googleapis_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return _RESPONDER.server_args(name, image, host, server_launch)


def ensure_googleapis_responder() -> None:
    _RESPONDER.ensure()


def googleapis_rm(name: str) -> None:
    remove(name)
