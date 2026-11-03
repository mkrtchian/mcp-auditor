"""hekmon8/Jenkins-server-mcp fix-check fixture: CVE-2026-10276 (SSRF through `jobPath`).

get_build_log and get_build_status fetch `/${jobPath}/${buildNumber}/consoleText` and
`/${jobPath}/${buildNumber}/api/json` on the configured Jenkins host. On the vulnerable build
(b1f32a7a5e0c) validateJobPath blocks absolute schemes but not percent-encoded traversal, so
`job/public/%2e%2e/%2e%2e/internal/secret` escapes the job namespace and reaches an internal path
of the same host: reach = internal_fetch. The patched build (dcee5f1aa4b3) rejects it. There is one
exploit per counted tool.

The shared singleton responder cannot carry the witness, since check_fix plants a fresh random
nonce per exercise: the builder stands its own responder of the same image with that nonce, on the
backend's bridge, and reaps it when the launch ends. It serves the nonce on any `/internal/` path
and a fixed benign body elsewhere. The server's `JENKINS_URL` is overridden to that responder with
a `-e`, which wins over the image's baked `ENV`. The responder is not the server and carries
neither the flaw nor the fix.
"""

import re
import secrets
import subprocess
import time
from collections.abc import Generator
from contextlib import contextmanager

from evals.cve_grammar import MechanismClass
from evals.cve_places import Coordinates, Place, Places, PlantKind
from evals.cve_planting import (
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    confinement_args,
    unprivileged_user_args,
)
from evals.cve_planting_base import LABEL, own_network_args
from evals.holdout_kit.fix_check import FixCheckTarget
from evals.holdout_kit.kit_client import KitClient
from evals.holdout_kit.kit_launch import Launch, LaunchShape
from evals.jenkins_backend import (
    JENKINS_BRIDGE,
    JENKINS_LAUNCH_LOCK,
    JENKINS_RESPONDER_IMAGE,
    JENKINS_RESPONDER_IP,
    JENKINS_SUBNET,
    ensure_jenkins_responder,
    jenkins_rm,
)

WITNESS = Place(
    id="jenkins-10276-internal",
    family="fix_check",
    reachable_by=frozenset({"internal_fetch"}),
    kind=PlantKind.HTTP_ENDPOINT,
    coordinates=Coordinates(
        PlantKind.HTTP_ENDPOINT, host=JENKINS_RESPONDER_IP, path="/internal/secret"
    ),
)
# An exploit is aimed when its arguments carry the percent-encoded traversal. The benign job path
# has none, and the nonce is in the response, never in the arguments.
AIM = re.compile(r"%2e%2e", re.I)
HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)

_TRAVERSAL = {"jobPath": "job/public/%2e%2e/%2e%2e/internal/secret", "buildNumber": "1"}
_BENIGN = {"jobPath": "job/MyJob", "buildNumber": "lastBuild"}
_SERVER_LAUNCH: list[str] = []
# The singleton sits on the bridge's first address, the per-launch responders above it.
_FIRST_PER_LAUNCH_HOST = 100
_LAST_PER_LAUNCH_HOST = 250


def responder_args(name: str, nonce: str, address: str) -> list[str]:
    return [
        "run", "-d", "--rm",
        "--name", name,
        "--label", LABEL,
        *own_network_args(JENKINS_BRIDGE),
        "--ip", address,
        *confinement_args(),
        "--cap-add", "NET_BIND_SERVICE",
        "-e", f"WITNESS_NONCE={nonce}",
        JENKINS_RESPONDER_IMAGE,
    ]  # fmt: skip


def server_args(image: str, responder_address: str) -> list[str]:
    return [
        "run", "-i", "--rm",
        *confinement_args(),
        *own_network_args(JENKINS_BRIDGE),
        "-e", f"JENKINS_URL=http://{responder_address}",
        "-e", "JENKINS_USER=admin",
        "-e", "JENKINS_TOKEN=token",
        *unprivileged_user_args(),
        "-w", HOST.working_directory,
        image,
        *_SERVER_LAUNCH,
    ]  # fmt: skip


@contextmanager
def jenkins_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    with JENKINS_LAUNCH_LOCK:
        ensure_jenkins_responder()
    name = f"mcp-auditor-kit-jenkins-r-{secrets.token_hex(4)}"
    address = _per_launch_address()
    try:
        subprocess.run(
            ["docker", *responder_args(name, spec.nonces[WITNESS.id], address)],
            check=True,
            capture_output=True,
        )
        time.sleep(1.0)
        yield Launch(command="docker", args=server_args(image, address))
    finally:
        jenkins_rm(name)


def _per_launch_address() -> str:
    network = JENKINS_SUBNET.rsplit(".", 1)[0]
    host = _FIRST_PER_LAUNCH_HOST + secrets.randbelow(
        _LAST_PER_LAUNCH_HOST - _FIRST_PER_LAUNCH_HOST
    )
    return f"{network}.{host}"


async def _exploit_build_log(places: Places, client: KitClient) -> None:
    await client.call_tool("get_build_log", _TRAVERSAL)


async def _exploit_build_status(places: Places, client: KitClient) -> None:
    await client.call_tool("get_build_status", _TRAVERSAL)


async def _benign_build_log(places: Places, client: KitClient) -> None:
    await client.call_tool("get_build_log", _BENIGN)


async def _benign_build_status(places: Places, client: KitClient) -> None:
    await client.call_tool("get_build_status", _BENIGN)


TARGET = FixCheckTarget(
    flaw="CVE-2026-10276",
    mechanism=MechanismClass.INTERNAL_FETCH,
    aim=AIM,
    witness=WITNESS,
    planting_host=HOST,
    builder=jenkins_env,
    exploits=(_exploit_build_log, _exploit_build_status),
    benign_calls=(_benign_build_log, _benign_build_status),
    vulnerable_service="jenkins-vuln",
    patched_service="jenkins",
    server_patched_service=None,
)

TARGETS = (TARGET,)
