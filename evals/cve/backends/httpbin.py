"""The httpbin backend's lifecycle: httpbin built from its repository, behind an HTTPS front.

The gateway's REST tool `fetch-report` GETs `https://httpbin.org/json`, sending a call's arguments
as the query string. httpbin.org is postmanlabs/httpbin, which publishes no release and no image:
its README builds the repository, and `Dockerfile.httpbin` repeats that repository's own Dockerfile
at the commit pinned there. httpbin.org terminates TLS in front of it, so a front
(`Dockerfile.httpbin-front`) serves the name httpbin.org on 443 and 80 from the name's leaf of the
fixture authority and its key, mounted read-only, and forwards the scheme in `X-Forwarded-Proto`,
which httpbin reads to mark its cookies Secure behind a TLS-terminating proxy.

Both parts sit on one closed labeled bridge on the global /24 that holds httpbin.org's address,
the front at that address, since the gateway's SSRF guard refuses a private or link-local one.
The server joins the bridge, reaches the front through an `--add-host` entry and trusts its leaf
through SSL_CERT_FILE, the fixture authority mounted read-only. The backend is a singleton, stood
once and reused across a server's concurrent nuisance runs, reaped by the generic orphan sweep, so
no lock is held across the yield. Both parts run under the confinement with no capability
added back: httpbin binds 8080 as its uid 10001 and nginx-unprivileged binds 80 and 443 as uid 101,
a container's net.ipv4.ip_unprivileged_port_start being 0.
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
from evals.cve.nuisance.confinement import labelled_run_args, running_with_launch, user_args
from evals.cve.planting_base import LABEL, PlantingHost, confinement_args, own_network_args
from evals.cve.public_stand_ins import stand_in_files

HTTPBIN_BRIDGE = "mcp-auditor-cve-httpbin-bridge"
_HTTPBIN_SUBNET = "44.209.237.0/24"  # httpbin.org's address, so the patched SSRF guard passes
HTTPBIN_FRONT_IP = "44.209.237.184"
HTTPBIN_NAME = "httpbin.org"
_AUTHORITY_PATH = "/etc/ssl/extra-ca.pem"
_READY_SECONDS = 120.0

# The backend is a singleton, so a caller does not hold this across its yield: a server's
# concurrent runs share it. A plain Lock serialises only the stand-up, since __enter__ and __exit__
# may run on different worker threads.
HTTPBIN_LAUNCH_LOCK = threading.Lock()

_FILES = stand_in_files(HTTPBIN_NAME)


@dataclass(frozen=True)
class HttpbinPart:
    container: str
    service: str  # the compose service building its image
    ip: str
    alias: str | None = None  # the name the front reaches it by
    mounts: tuple[tuple[Path, str], ...] = ()  # read-only, host path to container path

    @property
    def image(self) -> str:
        return f"mcp-auditor-cve-{self.service}:local"

    def run_args(self) -> list[str]:
        return [
            "run", "-d",
            "--name", self.container,
            "--label", LABEL,
            *own_network_args(HTTPBIN_BRIDGE),
            "--ip", self.ip,
            *(["--network-alias", self.alias] if self.alias else []),
            *confinement_args(),
            *(arg for mount in self.mounts for arg in _read_only(*mount)),
            self.image,
        ]  # fmt: skip


def _read_only(host_path: Path, container_path: str) -> tuple[str, str]:
    return ("-v", f"{host_path}:{container_path}:ro")


_APP = HttpbinPart("mcp-auditor-cve-httpbin", "httpbin", "44.209.237.2", "httpbin")
_FRONT = HttpbinPart(
    "mcp-auditor-cve-httpbin-front",
    "httpbin-front",
    HTTPBIN_FRONT_IP,
    mounts=(
        (_FILES.certificate, f"/etc/nginx/tls/{HTTPBIN_NAME}.pem"),
        (_FILES.key, f"/etc/nginx/tls/{HTTPBIN_NAME}-key.pem"),
    ),
)
HTTPBIN_PARTS = (_APP, _FRONT)
HTTPBIN_IMAGE = _APP.image
MOUNTED_FILES: tuple[Path, ...] = (_FILES.certificate, _FILES.key, _FILES.authority)


def httpbin_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return [
        "run", "-i", "--rm",
        *confinement_args(),
        "--name", name,
        "--label", LABEL,
        *own_network_args(HTTPBIN_BRIDGE),
        "--add-host", f"{HTTPBIN_NAME}:{HTTPBIN_FRONT_IP}",
        "-e", f"SSL_CERT_FILE={_AUTHORITY_PATH}",
        *_read_only(_FILES.authority, _AUTHORITY_PATH),
        *user_args(host.user),
        "-w", host.working_directory,
        image,
        *server_launch,
    ]  # fmt: skip


def ensure_httpbin_backend() -> None:
    for part in HTTPBIN_PARTS:
        _ensure_image(part)
    ensure_closed_network(HTTPBIN_BRIDGE, "--subnet", _HTTPBIN_SUBNET)
    for part in HTTPBIN_PARTS:
        _ensure_running(part)
    _wait_until_httpbin_answers()


def _ensure_image(part: HttpbinPart) -> None:
    if _run("docker", "image", "inspect", part.image, check=False).returncode != 0:
        dockerfile = image_dockerfile(part.service)
        _run(
            "docker", "build", "-t", part.image, "-f", str(dockerfile), str(DOCKER_DIRECTORY),
            timeout=1800.0,
        )  # fmt: skip


def _ensure_running(part: HttpbinPart) -> None:
    if running_with_launch(part.container, part.run_args()):
        return
    remove(part.container)
    _run("docker", *labelled_run_args(part.run_args()))


def _wait_until_httpbin_answers() -> None:
    status = "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/status/200')"
    probe = ("docker", "exec", _APP.container, "python", "-c", status)
    deadline = time.monotonic() + _READY_SECONDS
    while _run(*probe, check=False).returncode != 0:
        if time.monotonic() > deadline:
            raise RuntimeError(f"{_APP.container} did not answer within {_READY_SECONDS:.0f}s")
        time.sleep(1)


def httpbin_rm(name: str) -> None:
    remove(name)


def _run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


LIFECYCLE = BackendLifecycle(
    "httpbin", HTTPBIN_LAUNCH_LOCK, ensure_httpbin_backend, httpbin_server_args, httpbin_rm
)
