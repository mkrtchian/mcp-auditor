"""The CKAN API responder backend's lifecycle.

A light HTTP/HTTPS responder that answers CKAN success:true envelopes so a patched
@aborruso/ckan-mcp-server's benign tool calls answer without error. Unlike the Doris cluster it
is cheap to stand, but like it the responder is a singleton on a fixed address: stood once and
reused across a server's concurrent nuisance runs, reaped by the generic orphan sweep, so no
lock is held across the yield.

The audited server reaches the responder as an outbound CKAN API, not over MCP stdio. The
patched server resolves each request host and rejects a private / link-local address, so the
responder sits at a public-range (TEST-NET-3) static IP on its own bridge and the dati.gov.it /
data.europa.eu hosts are DNS-aliased to it with `--add-host`. HTTPS is self-signed and the
server runs with `NODE_TLS_REJECT_UNAUTHORIZED=0`, because the CKAN portal rewrite forces the
dati.gov.it base URL to https and the MQA URLs are hardcoded https.

A caller drives this through `ensure_ckan_responder`, `ckan_server_args`, `ckan_rm` and
`CKAN_LAUNCH_LOCK`, built on the user resolution and container profile of `doris_backend` and
`cve_planting`.
"""

import subprocess
import threading
from collections.abc import Sequence
from contextlib import suppress

from evals.cve_planting import confinement_args
from evals.cve_planting_base import LABEL, PlantingHost
from evals.cve_targets import DOCKER_DIRECTORY
from evals.doris_backend import user_args

CKAN_RESPONDER_IMAGE = "mcp-auditor-cve-ckan-responder:local"
CKAN_RESPONDER_CONTAINER = "mcp-auditor-cve-ckan-responder"
CKAN_BRIDGE = "mcp-auditor-cve-ckan-bridge"  # server <-> responder, static public-range IPs
_CKAN_SUBNET = "203.0.113.0/24"  # TEST-NET-3: public-looking, so the patched SSRF guard passes
CKAN_RESPONDER_IP = "203.0.113.2"
# The hosts the audited server resolves to the responder: the dati.gov.it portal the CKAN tools
# and the MQA server_url target, and the data.europa.eu endpoint the MQA cache/metrics fetch hits.
CKAN_ALIASES: tuple[str, ...] = ("www.dati.gov.it", "dati.gov.it", "data.europa.eu")

# The responder is a singleton on a fixed IP, so a caller does not hold this across its yield: a
# server's concurrent runs share the one responder. A plain Lock, like DORIS_LAUNCH_LOCK, serialises
# only the stand-up, since __enter__ and __exit__ may run on different worker threads.
CKAN_LAUNCH_LOCK = threading.Lock()

_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.ckan-responder"


def ckan_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return [
        "run", "-i", "--rm",
        *confinement_args(),
        "--name", name,
        "--label", LABEL,
        "--network", CKAN_BRIDGE,
        *_alias_args(),
        "-e", "NODE_TLS_REJECT_UNAUTHORIZED=0",
        *user_args(host.user),
        "-w", host.working_directory,
        image,
        *server_launch,
    ]  # fmt: skip


def _alias_args() -> list[str]:
    args: list[str] = []
    for host in CKAN_ALIASES:
        args += ["--add-host", f"{host}:{CKAN_RESPONDER_IP}"]
    return args


def ensure_ckan_responder() -> None:
    _ensure_image()
    _ensure_network()
    if not _responder_running():
        if _responder_exists():
            ckan_rm(CKAN_RESPONDER_CONTAINER)
        _ckan_run(
            "docker", "run", "-d",
            "--name", CKAN_RESPONDER_CONTAINER,
            "--label", LABEL,
            "--network", CKAN_BRIDGE,
            "--ip", CKAN_RESPONDER_IP,
            *confinement_args(),
            "--cap-add", "NET_BIND_SERVICE",  # root behind cap-drop ALL still binds 80/443
            CKAN_RESPONDER_IMAGE,
        )  # fmt: skip


def _ensure_image() -> None:
    present = _ckan_run("docker", "image", "inspect", CKAN_RESPONDER_IMAGE, check=False)
    if present.returncode != 0:
        _ckan_run(
            "docker", "build", "-t", CKAN_RESPONDER_IMAGE, "-f", str(_DOCKERFILE),
            str(DOCKER_DIRECTORY), timeout=600.0,
        )  # fmt: skip


def _ensure_network() -> None:
    listed = _ckan_run("docker", "network", "ls", "--format", "{{.Name}}", check=False)
    if CKAN_BRIDGE in listed.stdout.split():
        return
    _ckan_run(
        "docker", "network", "create", "--label", LABEL, "--subnet", _CKAN_SUBNET, CKAN_BRIDGE
    )


def _responder_running() -> bool:
    return CKAN_RESPONDER_CONTAINER in _responder_names("docker", "ps")


def _responder_exists() -> bool:
    return CKAN_RESPONDER_CONTAINER in _responder_names("docker", "ps", "-a")


def _responder_names(*ps_command: str) -> list[str]:
    result = _ckan_run(
        *ps_command,
        "--filter", f"name=^{CKAN_RESPONDER_CONTAINER}$", "--format", "{{.Names}}", check=False,
    )  # fmt: skip
    return result.stdout.split()


def _ckan_run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


def ckan_rm(name: str) -> None:
    with suppress(subprocess.SubprocessError, OSError):
        _ckan_run("docker", "rm", "-f", name, check=False)
