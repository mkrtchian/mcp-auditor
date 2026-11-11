"""hekmon8/Jenkins-server-mcp fix-check fixture: CVE-2026-10276 (SSRF through `jobPath`).

Four tools compose a Jenkins request path from `jobPath`: get_build_status fetches
`/${jobPath}/${buildNumber}/api/json`, get_build_log `/${jobPath}/${buildNumber}/consoleText`,
get_failed_build_log `/${jobPath}/api/json` then the failed build's console, and trigger_build posts
to `/${jobPath}/build`. The vulnerable build (b1f32a7a5e0c) predates validateJobPath and puts
`jobPath` into the path unvalidated, so `job/public/%2e%2e/%2e%2e/userContent/internal/secret`
escapes the job namespace and reaches an internal path of the same host: reach = internal_fetch. The
patched build (dcee5f1aa4b3) rejects the encoded traversal in all four, the shared validateJobPath
guard. get_build_log and get_build_status read the reached path back, so their exploits surface the
witness; trigger_build and get_failed_build_log go through the same guard but return a fixed text or
a build lookup, so their exploits are aimed without surfacing (either surfacing is enough for the
verdict).

The backend is the real Jenkins controller. The shared singleton cannot carry the witness, since
check_fix plants a fresh random nonce per exercise: the builder stands its own Jenkins of the same
image on the backend's bridge, writes the nonce into that Jenkins's `userContent` tree (served by
Jenkins itself at `/userContent/`, outside every job), and reaps it when the launch ends. The
per-launch controller keeps the holdout confinement without the memory bound, as every per-launch
fix-check container does. The server's `JENKINS_URL` is overridden to that Jenkins with a `-e`,
which wins over the image's baked `ENV`. Jenkins is not the server and carries neither the flaw nor
the fix.
"""

import re
import secrets
import subprocess
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from evals.closed_network import ensure_closed_network
from evals.cve.kit.client import KitClient
from evals.cve.kit.fix_check import FixCheckTarget
from evals.cve.kit.launch import Launch, LaunchShape
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
from evals.jenkins_backend import (
    JENKINS_BRIDGE,
    JENKINS_LAUNCH_LOCK,
    JENKINS_PORT,
    JENKINS_RESPONDER_IMAGE,
    JENKINS_RESPONDER_IP,
    JENKINS_SUBNET,
    ensure_jenkins_image,
    wait_until_up,
)

WITNESS = Place(
    id="jenkins-10276-internal",
    family="fix_check",
    reachable_by=frozenset({"internal_fetch"}),
    kind=PlantKind.HTTP_ENDPOINT,
    coordinates=Coordinates(
        PlantKind.HTTP_ENDPOINT, host=JENKINS_RESPONDER_IP, path="/userContent/internal/secret"
    ),
)
# An exploit is aimed when its arguments carry the percent-encoded traversal. The benign job path
# has none, and the nonce is in the response, never in the arguments.
AIM = re.compile(r"%2e%2e", re.I)
HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)

_TRAVERSAL = "job/public/%2e%2e/%2e%2e/userContent/internal/secret"
_EXPLOIT_BUILD = {"jobPath": _TRAVERSAL, "buildNumber": "1"}
_EXPLOIT_JOB = {"jobPath": _TRAVERSAL}
_EXPLOIT_TRIGGER: dict[str, Any] = {"jobPath": _TRAVERSAL, "parameters": {}}
_BENIGN_BUILD = {"jobPath": "job/MyJob", "buildNumber": "lastBuild"}
_BENIGN_JOB = {"jobPath": "job/MyJob"}
_BENIGN_TRIGGER: dict[str, Any] = {"jobPath": "job/MyJob", "parameters": {}}
_SERVER_LAUNCH: list[str] = []
# The singleton sits on the bridge's first address, the per-launch controllers above it.
_FIRST_PER_LAUNCH_HOST = 100
_LAST_PER_LAUNCH_HOST = 250


def controller_args(name: str, address: str) -> list[str]:
    # The per-launch Jenkins the witness is planted in: the backend image, the holdout confinement
    # without the memory bound, no capability, its own address on the backend's bridge.
    return [
        "run", "-d",
        "--name", name,
        "--label", LABEL,
        *own_network_args(JENKINS_BRIDGE),
        "--ip", address,
        *confinement_args(),
        JENKINS_RESPONDER_IMAGE,
    ]  # fmt: skip


def plant_args(name: str, nonce: str) -> list[str]:
    # The witness sits in Jenkins's own userContent tree, at the build-shaped paths the read tools
    # append to jobPath; Jenkins serves it to an authenticated reader as any userContent file.
    script = (
        'd="$JENKINS_HOME/userContent/internal/secret/1"; mkdir -p "$d/api"'
        ' && printf %s "$W" > "$d/consoleText"'
        ' && printf \'{"result":"%s"}\' "$W" > "$d/api/json"'
    )
    return ["exec", "-e", f"W={nonce}", name, "sh", "-c", script]


def server_args(image: str, controller_address: str) -> list[str]:
    return [
        "run", "-i", "--rm",
        *confinement_args(),
        *own_network_args(JENKINS_BRIDGE),
        "-e", f"JENKINS_URL=http://{controller_address}:{JENKINS_PORT}",
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
        ensure_jenkins_image()
        ensure_closed_network(JENKINS_BRIDGE, "--subnet", JENKINS_SUBNET)
    name = f"mcp-auditor-kit-jenkins-{secrets.token_hex(4)}"
    address = _per_launch_address()
    try:
        _run("docker", *controller_args(name, address))
        wait_until_up(name)
        _run("docker", *plant_args(name, spec.nonces[WITNESS.id]))
        yield Launch(command="docker", args=server_args(image, address))
    finally:
        subprocess.run(["docker", "rm", "-f", "-v", name], check=False, capture_output=True)


def _per_launch_address() -> str:
    network = JENKINS_SUBNET.rsplit(".", 1)[0]
    host = _FIRST_PER_LAUNCH_HOST + secrets.randbelow(
        _LAST_PER_LAUNCH_HOST - _FIRST_PER_LAUNCH_HOST
    )
    return f"{network}.{host}"


def _run(*args: str) -> None:
    subprocess.run(list(args), check=True, capture_output=True)


async def _exploit_build_log(places: Places, client: KitClient) -> None:
    await client.call_tool("get_build_log", _EXPLOIT_BUILD)


async def _exploit_build_status(places: Places, client: KitClient) -> None:
    await client.call_tool("get_build_status", _EXPLOIT_BUILD)


async def _exploit_trigger_build(places: Places, client: KitClient) -> None:
    await client.call_tool("trigger_build", _EXPLOIT_TRIGGER)


async def _exploit_failed_build_log(places: Places, client: KitClient) -> None:
    await client.call_tool("get_failed_build_log", _EXPLOIT_JOB)


async def _benign_build_log(places: Places, client: KitClient) -> None:
    await client.call_tool("get_build_log", _BENIGN_BUILD)


async def _benign_build_status(places: Places, client: KitClient) -> None:
    await client.call_tool("get_build_status", _BENIGN_BUILD)


async def _benign_trigger_build(places: Places, client: KitClient) -> None:
    await client.call_tool("trigger_build", _BENIGN_TRIGGER)


async def _benign_failed_build_log(places: Places, client: KitClient) -> None:
    await client.call_tool("get_failed_build_log", _BENIGN_JOB)


TARGET = FixCheckTarget(
    flaw="CVE-2026-10276",
    mechanism=MechanismClass.INTERNAL_FETCH,
    aim=AIM,
    witness=WITNESS,
    planting_host=HOST,
    builder=jenkins_env,
    exploits=(
        _exploit_build_log,
        _exploit_build_status,
        _exploit_trigger_build,
        _exploit_failed_build_log,
    ),
    benign_calls=(
        _benign_build_log,
        _benign_build_status,
        _benign_trigger_build,
        _benign_failed_build_log,
    ),
    vulnerable_service="jenkins-vuln",
    patched_service="jenkins",
    server_patched_service=None,
)

TARGETS = (TARGET,)
