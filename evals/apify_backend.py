"""The Apify documentation responder backend's lifecycle.

A light TLS responder standing in for the documentation host the `fetch-apify-docs` tool of
@apify/actors-mcp-server fetches from. It serves a fixed benign page on `docs.apify.com` and, on
the suffix host `docs.apify.com.<name>` that the vulnerable `startsWith` allowlist lets through,
a page carrying `WITNESS_NONCE` when it is set. Like the CKAN responder it is cheap to stand and
a singleton on a fixed address: stood once and reused across a server's concurrent nuisance
runs, reaped by the generic orphan sweep, so no lock is held across the yield. The singleton
carries no witness nonce, so it serves the run-phase benign call only: a fix-check stands its
own container of the same image with `WITNESS_NONCE` set, on the bridge and subnet exported here.

A second singleton on the same bridge stands in for `api.apify.com` (`API_HOST`), which the
server calls at start: the generic stand-in image replays the committed capture
(`evals/stand_ins/api.apify.com.json`), mounted read-only with its leaf and key. Only the paths
are named here, Docker reads them at `docker run`, so importing this module reads no file. A
fix-check stands no stand-in of its own: its server reaches this singleton.

The audited server reaches both as outbound HTTPS fetches, not over MCP stdio. The documentation
names are DNS-aliased to the responder and the API name to its stand-in with `--add-host`, and
neither cert chains to a root the server trusts, so it runs with `NODE_TLS_REJECT_UNAUTHORIZED=0`.
The aliases and that setting are `docker run` arguments of the server's own container
(`apify_network_args`, which also carries the dummy `APIFY_TOKEN` the server refuses to start
without), not the auditor's `--env` flag. The responders sit in the RFC 2544 benchmarking range
on their own bridge: the allowlist is hostname-based, the range only has to differ from the
other responders'.

A caller drives this through `ensure_apify_responder`, `apify_server_args`, `apify_rm` and
`APIFY_LAUNCH_LOCK`, built on the shared lifecycle of `responder_backend`.
"""

import threading
from collections.abc import Sequence

from evals.backend_lifecycle import BackendLifecycle
from evals.cve_planting_base import STAND_IN_IMAGE, STAND_IN_SERVICE, PlantingHost
from evals.docker_paths import DOCKER_DIRECTORY, image_dockerfile
from evals.public_stand_ins import stand_in_files
from evals.responder_backend import Responder, remove

APIFY_RESPONDER_IMAGE = "mcp-auditor-cve-apify-responder:local"
APIFY_RESPONDER_CONTAINER = "mcp-auditor-cve-apify-responder"
APIFY_RESPONDER_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.apify-responder"
APIFY_BRIDGE = "mcp-auditor-cve-apify-bridge"  # server <-> responder, static IPs
APIFY_SUBNET = "198.18.1.0/24"  # RFC 2544: overlaps no other responder's subnet
APIFY_RESPONDER_IP = "198.18.1.2"
APIFY_BENIGN_HOST = "docs.apify.com"
APIFY_SUFFIX_HOST = f"{APIFY_BENIGN_HOST}.example.test"
API_HOST = "api.apify.com"
_API_STAND_IN_IP = "198.18.1.3"  # a fix-check's own responders sit at .100 to .250

# The responder is a singleton on a fixed IP, so a caller does not hold this across its yield: a
# server's concurrent runs share the one responder. A plain Lock serialises only the stand-up,
# since __enter__ and __exit__ may run on different worker threads.
APIFY_LAUNCH_LOCK = threading.Lock()

_RESPONDER = Responder(
    image=APIFY_RESPONDER_IMAGE,
    container=APIFY_RESPONDER_CONTAINER,
    bridge=APIFY_BRIDGE,
    subnet=APIFY_SUBNET,
    ip=APIFY_RESPONDER_IP,
    dockerfile=APIFY_RESPONDER_DOCKERFILE,
)


def _read_only_mounts() -> tuple[str, ...]:
    files = stand_in_files(API_HOST)
    mounts = (
        (files.capture, "capture.json"),
        (files.certificate, "cert.pem"),
        (files.key, "key.pem"),
    )
    return tuple(arg for path, name in mounts for arg in ("-v", f"{path}:/stand-in/{name}:ro"))


_API_STAND_IN = Responder(
    image=STAND_IN_IMAGE,
    container="mcp-auditor-cve-apify-api-stand-in",
    bridge=APIFY_BRIDGE,
    subnet=APIFY_SUBNET,
    ip=_API_STAND_IN_IP,
    dockerfile=image_dockerfile(STAND_IN_SERVICE),
    run_args=_read_only_mounts(),
)


def apify_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    extra = apify_network_args(APIFY_RESPONDER_IP)
    return _RESPONDER.server_args(name, image, host, server_launch, extra)


def apify_network_args(responder_address: str) -> list[str]:
    args: list[str] = []
    for host in (APIFY_BENIGN_HOST, APIFY_SUFFIX_HOST):
        args += ["--add-host", f"{host}:{responder_address}"]
    args += ["--add-host", f"{API_HOST}:{_API_STAND_IN_IP}"]
    return [*args, "-e", "NODE_TLS_REJECT_UNAUTHORIZED=0", "-e", "APIFY_TOKEN=calib-token"]


def ensure_apify_responder() -> None:
    _RESPONDER.ensure()
    _API_STAND_IN.ensure()


def apify_rm(name: str) -> None:
    remove(name)


LIFECYCLE = BackendLifecycle(
    "apify", APIFY_LAUNCH_LOCK, ensure_apify_responder, apify_server_args, apify_rm
)
