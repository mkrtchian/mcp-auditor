"""The ContextForge REST responder backend's lifecycle.

A light HTTP responder that answers a benign body so a patched IBM ContextForge MCP Gateway's
benign REST tool call answers without error. Like the CKAN responder it is cheap to stand and a
singleton on a fixed address: stood once and reused across a server's concurrent nuisance runs,
reaped by the generic orphan sweep, so no lock is held across the yield.

The audited gateway reaches the responder as an outbound REST fetch, not over MCP stdio. The
patched 1.0.7 gateway re-resolves and pins the REST tool's host at invocation and rejects a private
/ link-local address, so the responder sits at a public-range (TEST-NET-2) static IP on its own
bridge and the benign REST tool points straight at that IP.

A caller drives this through `ensure_contextforge_responder`, `contextforge_server_args`,
`contextforge_rm` and `CONTEXTFORGE_LAUNCH_LOCK`, built on the user resolution and container profile
of `doris_backend` and `cve_planting`.
"""

import subprocess
import threading
from collections.abc import Sequence
from contextlib import suppress

from evals.cve_planting import confinement_args
from evals.cve_planting_base import LABEL, PlantingHost
from evals.cve_targets import DOCKER_DIRECTORY
from evals.doris_backend import user_args

CONTEXTFORGE_RESPONDER_IMAGE = "mcp-auditor-cve-contextforge-responder:local"
CONTEXTFORGE_RESPONDER_CONTAINER = "mcp-auditor-cve-contextforge-responder"
CONTEXTFORGE_BRIDGE = "mcp-auditor-cve-contextforge-bridge"  # gateway <-> responder, static IPs
_CONTEXTFORGE_SUBNET = "198.51.100.0/24"  # TEST-NET-2: public-looking, so the SSRF guard passes
CONTEXTFORGE_RESPONDER_IP = "198.51.100.2"  # the benign REST tool's target

# The responder is a singleton on a fixed IP, so a caller does not hold this across its yield: a
# server's concurrent runs share the one responder. A plain Lock serialises only the stand-up,
# since __enter__ and __exit__ may run on different worker threads.
CONTEXTFORGE_LAUNCH_LOCK = threading.Lock()

_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.contextforge-responder"


def contextforge_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return [
        "run", "-i", "--rm",
        *confinement_args(),
        "--name", name,
        "--label", LABEL,
        "--network", CONTEXTFORGE_BRIDGE,
        *user_args(host.user),
        "-w", host.working_directory,
        image,
        *server_launch,
    ]  # fmt: skip


def ensure_contextforge_responder() -> None:
    _ensure_image()
    _ensure_network()
    if not _responder_running():
        if _responder_exists():
            contextforge_rm(CONTEXTFORGE_RESPONDER_CONTAINER)
        _contextforge_run(
            "docker", "run", "-d",
            "--name", CONTEXTFORGE_RESPONDER_CONTAINER,
            "--label", LABEL,
            "--network", CONTEXTFORGE_BRIDGE,
            "--ip", CONTEXTFORGE_RESPONDER_IP,
            *confinement_args(),
            "--cap-add", "NET_BIND_SERVICE",  # root behind cap-drop ALL still binds 80
            CONTEXTFORGE_RESPONDER_IMAGE,
        )  # fmt: skip


def _ensure_image() -> None:
    present = _contextforge_run(
        "docker", "image", "inspect", CONTEXTFORGE_RESPONDER_IMAGE, check=False
    )
    if present.returncode != 0:
        _contextforge_run(
            "docker", "build", "-t", CONTEXTFORGE_RESPONDER_IMAGE, "-f", str(_DOCKERFILE),
            str(DOCKER_DIRECTORY), timeout=600.0,
        )  # fmt: skip


def _ensure_network() -> None:
    listed = _contextforge_run("docker", "network", "ls", "--format", "{{.Name}}", check=False)
    if CONTEXTFORGE_BRIDGE in listed.stdout.split():
        return
    _contextforge_run(
        "docker", "network", "create",
        "--label", LABEL, "--subnet", _CONTEXTFORGE_SUBNET, CONTEXTFORGE_BRIDGE,
    )  # fmt: skip


def _responder_running() -> bool:
    return CONTEXTFORGE_RESPONDER_CONTAINER in _responder_names("docker", "ps")


def _responder_exists() -> bool:
    return CONTEXTFORGE_RESPONDER_CONTAINER in _responder_names("docker", "ps", "-a")


def _responder_names(*ps_command: str) -> list[str]:
    result = _contextforge_run(
        *ps_command,
        "--filter", f"name=^{CONTEXTFORGE_RESPONDER_CONTAINER}$", "--format", "{{.Names}}",
        check=False,
    )  # fmt: skip
    return result.stdout.split()


def _contextforge_run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


def contextforge_rm(name: str) -> None:
    with suppress(subprocess.SubprocessError, OSError):
        _contextforge_run("docker", "rm", "-f", name, check=False)
