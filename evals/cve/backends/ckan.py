"""The CKAN backend's lifecycle: the real CKAN portal, and a stand-in for data.europa.eu.

The server's CKAN tools call a CKAN portal's Action API (`{server_url}/api/3/action/<action>`),
and its MQA tools call dati.gov.it's `package_show` then data.europa.eu's MQA cache and metrics.
CKAN runs here: the stack CKAN's Docker Compose install (ckan-docker) brings up, PostgreSQL,
Solr, Redis and CKAN 2.12.1, each in its own container under the nuisance confinement, behind an
HTTPS front that serves it under the real names the benign calls use (www.dati.gov.it under
/opendata, where the server rewrites every dati.gov.it alias, and demo.ckan.org at its root).
data.europa.eu (piveau's MQA, fed by the EU portal's harvest of dati.gov.it) cannot run here:
the stand-in image serves its capture (`evals/stand_ins/data.europa.eu.json`) under its real
name. A loader in the CKAN image writes what CKAN's documentation gives, once the portal answers.

Everything sits on one closed labeled bridge (no route to the host or the Internet), each part at
a fixed address, so no part takes the address the server resolves another to. The patched server
rejects a name that resolves to a private address, so the bridge is a public-range (TEST-NET-3)
subnet, and the server reaches the front and the stand-in through `--add-host` entries. It trusts
their leaves through NODE_EXTRA_CA_CERTS, the fixture authority mounted read-only (ADR 034). The
stack is a singleton, stood once and reused across a server's concurrent nuisance runs, reaped by
the generic orphan sweep, so no lock is held across the yield. Every container binds its ports as
its image's own user or, for the stand-in, as a root with no capability: a container's
net.ipv4.ip_unprivileged_port_start is 0.
"""

import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from evals.cve.backends.lifecycle import BackendLifecycle
from evals.cve.backends.responder import remove
from evals.cve.closed_network import ensure_closed_network
from evals.cve.docker_paths import DOCKER_DIRECTORY, image_dockerfile
from evals.cve.nuisance.confinement import (
    labelled_run_args,
    nuisance_confinement_args,
    running_with_launch,
    user_args,
)
from evals.cve.planting_base import LABEL, STAND_IN_SERVICE, PlantingHost, own_network_args
from evals.cve.public_stand_ins import stand_in_files

CKAN_BRIDGE = "mcp-auditor-cve-ckan-bridge"
_CKAN_SUBNET = "203.0.113.0/24"  # TEST-NET-3: public-looking, so the patched SSRF guard passes
CKAN_FRONT_IP = "203.0.113.2"
EUROPA_IP = "203.0.113.3"
CKAN_NAMES: tuple[str, ...] = ("www.dati.gov.it", "demo.ckan.org")
EUROPA_NAME = "data.europa.eu"
_AUTHORITY_PATH = "/etc/ssl/extra-ca.pem"
_READY_SECONDS = 600.0

# The stack is a singleton, so a caller does not hold this across its yield: a server's concurrent
# runs share it. A plain Lock serialises only the stand-up, since __enter__ and __exit__ may run on
# different worker threads.
CKAN_LAUNCH_LOCK = threading.Lock()


@dataclass(frozen=True)
class BackendPart:
    container: str
    service: str  # the compose service building its image
    ip: str
    alias: str | None = None  # the name the other parts reach it by
    mounts: tuple[tuple[Path, str], ...] = ()  # read-only, host path to container path

    @property
    def image(self) -> str:
        return f"mcp-auditor-cve-{self.service}:local"

    def run_args(self) -> list[str]:
        return [
            "run", "-d",
            "--name", self.container,
            "--label", LABEL,
            *own_network_args(CKAN_BRIDGE),
            "--ip", self.ip,
            *(["--network-alias", self.alias] if self.alias else []),
            *nuisance_confinement_args(),
            *(
                arg
                for host_path, container_path in self.mounts
                for arg in _read_only(host_path, container_path)
            ),
            self.image,
        ]  # fmt: skip


def _read_only(host_path: Path, container_path: str) -> tuple[str, str]:
    return ("-v", f"{host_path}:{container_path}:ro")


def _front_mounts() -> tuple[tuple[Path, str], ...]:
    leaves = (stand_in_files(name) for name in CKAN_NAMES)
    return tuple(
        mount
        for name, files in zip(CKAN_NAMES, leaves, strict=True)
        for mount in (
            (files.certificate, f"/etc/nginx/tls/{name}.pem"),
            (files.key, f"/etc/nginx/tls/{name}-key.pem"),
        )
    )


_EUROPA_FILES = stand_in_files(EUROPA_NAME)

_DB = BackendPart("mcp-auditor-cve-ckan-db", "ckan-db", "203.0.113.11", "db")
_SOLR = BackendPart("mcp-auditor-cve-ckan-solr", "ckan-solr", "203.0.113.12", "solr")
_REDIS = BackendPart("mcp-auditor-cve-ckan-redis", "ckan-redis", "203.0.113.13", "redis")
_PORTAL = BackendPart("mcp-auditor-cve-ckan-portal", "ckan-portal", "203.0.113.14", "ckan")
_FRONT = BackendPart(
    "mcp-auditor-cve-ckan-front", "ckan-front", CKAN_FRONT_IP, mounts=_front_mounts()
)
_EUROPA = BackendPart(
    "mcp-auditor-cve-ckan-europa",
    STAND_IN_SERVICE,
    EUROPA_IP,
    mounts=(
        (_EUROPA_FILES.capture, "/stand-in/capture.json"),
        (_EUROPA_FILES.certificate, "/stand-in/cert.pem"),
        (_EUROPA_FILES.key, "/stand-in/key.pem"),
    ),
)
CKAN_PARTS = (_DB, _SOLR, _REDIS, _PORTAL, _FRONT, _EUROPA)
CKAN_IMAGE = _PORTAL.image
MOUNTED_FILES: tuple[Path, ...] = (
    *(host_path for part in CKAN_PARTS for host_path, _ in part.mounts),
    _EUROPA_FILES.authority,
)


def ckan_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return [
        "run", "-i", "--rm",
        *nuisance_confinement_args(),
        "--name", name,
        "--label", LABEL,
        *own_network_args(CKAN_BRIDGE),
        *_host_args(),
        "-e", f"NODE_EXTRA_CA_CERTS={_AUTHORITY_PATH}",
        *_read_only(_EUROPA_FILES.authority, _AUTHORITY_PATH),
        *user_args(host.user),
        "-w", host.working_directory,
        image,
        *server_launch,
    ]  # fmt: skip


def _host_args() -> list[str]:
    entries = [(name, CKAN_FRONT_IP) for name in CKAN_NAMES] + [(EUROPA_NAME, EUROPA_IP)]
    return [arg for name, ip in entries for arg in ("--add-host", f"{name}:{ip}")]


def ensure_ckan_backend() -> None:
    for part in CKAN_PARTS:
        _ensure_image(part)
    ensure_closed_network(CKAN_BRIDGE, "--subnet", _CKAN_SUBNET)
    for part in (_DB, _SOLR, _REDIS, _PORTAL):
        _ensure_running(part)
    _wait_until_the_portal_answers()
    _run("docker", "exec", _PORTAL.container, "python3", "/srv/app/load_example.py", timeout=300.0)
    for part in (_FRONT, _EUROPA):
        _ensure_running(part)


def _ensure_image(part: BackendPart) -> None:
    if _run("docker", "image", "inspect", part.image, check=False).returncode != 0:
        dockerfile = image_dockerfile(part.service)
        _run(
            "docker", "build", "-t", part.image, "-f", str(dockerfile), str(DOCKER_DIRECTORY),
            timeout=1800.0,
        )  # fmt: skip


def _ensure_running(part: BackendPart) -> None:
    if running_with_launch(part.container, part.run_args()):
        return
    remove(part.container)
    _run("docker", *labelled_run_args(part.run_args()))


def _wait_until_the_portal_answers() -> None:
    status = "http://localhost:5000/api/3/action/status_show"
    probe = ("docker", "exec", _PORTAL.container, "curl", "-fsS", "-o", "/dev/null", status)
    deadline = time.monotonic() + _READY_SECONDS
    while _run(*probe, check=False).returncode != 0:
        if time.monotonic() > deadline:
            raise RuntimeError(f"{_PORTAL.container} did not answer within {_READY_SECONDS:.0f}s")
        time.sleep(5)


def ckan_rm(name: str) -> None:
    remove(name)


def _run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


LIFECYCLE = BackendLifecycle(
    "ckan", CKAN_LAUNCH_LOCK, ensure_ckan_backend, ckan_server_args, ckan_rm
)
