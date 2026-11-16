"""The detection builder of CVE-2026-58485: the server launch of `ssrf_env`, with a real SearXNG
stood for the launch at the address mcp-searxng's README gives in its example,
`SEARXNG_URL=http://localhost:8080`.

SearXNG joins the namespace holder, so the server reaches it on the holder's loopback, and its
DuckDuckGo engine resolves `html.duckduckgo.com` through the holder's host entries to the
stand-in, as the server would. It trusts the fixture authority through `SSL_CERT_FILE`, the
variable its outgoing HTTP client reads (SearXNG's `outgoing` settings page). It runs under the
image's own `searxng` account: the entrypoint copies the settings template into
`/etc/searxng`, which that account owns, so the start needs no capability, where root with every
capability dropped is refused the copy. It is removed before the planting's holder.
"""

import secrets
import subprocess
import time
from collections.abc import Callable, Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass

from evals.cve.environments import Launch, LaunchShape, materialise
from evals.cve.layout import layout_mount_args, owned_layout
from evals.cve.planting import PlantingDocker, PlantingSpec, confinement_args, planted
from evals.cve.planting_base import LABEL, memory_bound_args
from evals.cve.planting_docker import DOCKER_PLANTING
from evals.cve.public_stand_ins import stand_in_files

SEARXNG_SERVICE = "searxng-backend"  # the compose service building the image
SEARXNG_IMAGE = f"mcp-auditor-cve-{SEARXNG_SERVICE}:local"
SEARXNG_URL = "http://localhost:8080"
_AUTHORITY_PATH = "/etc/ssl/extra-ca.pem"
_AUTHORITY = stand_in_files("html.duckduckgo.com").authority
_PIDS_LIMIT = "64"  # measured peak of 14 tasks through start and searches
_READY_SECONDS = 90.0  # measured ready in about 3 s


@dataclass(frozen=True)
class SearxngDocker:
    start: Callable[[Sequence[str]], None]  # the `docker` arguments of a detached run
    wait_ready: Callable[[str], None]
    remove: Callable[[str], None]


def _start(run_args: Sequence[str]) -> None:
    _docker(*run_args)


def _wait_ready(name: str) -> None:
    probe = ("exec", name, "wget", "-q", "-T", "2", "-O", "-", "http://127.0.0.1:8080/healthz")
    deadline = time.monotonic() + _READY_SECONDS
    while _docker(*probe, check=False).stdout.strip() != "OK":
        if _docker("inspect", "-f", "{{.State.Running}}", name).stdout.strip() != "true":
            logs = _docker("logs", name, check=False)
            raise RuntimeError(f"SearXNG {name} stopped before it answered: {logs.stderr}")
        if time.monotonic() > deadline:
            raise RuntimeError(f"SearXNG {name} did not answer within {_READY_SECONDS:.0f}s")
        time.sleep(0.5)


def _remove(name: str) -> None:
    _docker("rm", "-f", "-v", name, check=False)


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=60.0
    )


DOCKER_SEARXNG = SearxngDocker(_start, _wait_ready, _remove)


@contextmanager
def searxng_env(
    image: str,
    spec: PlantingSpec,
    shape: LaunchShape = LaunchShape.NORMAL,
    *,
    docker: PlantingDocker = DOCKER_PLANTING,
    searxng: SearxngDocker = DOCKER_SEARXNG,
) -> Generator[Launch]:
    name = f"{LABEL}-searxng-{secrets.token_hex(6)}"
    with (
        owned_layout(docker, lambda root: materialise(root, spec, shape)) as root,
        planted(spec, image, docker) as args,
    ):
        try:
            searxng.start(searxng_args(name, args.network))
            searxng.wait_ready(name)
            yield Launch(
                command="docker",
                args=[
                    "run",
                    "-i",
                    "--rm",
                    *confinement_args(),
                    *args.run_args(),
                    "-e",
                    f"SEARXNG_URL={SEARXNG_URL}",
                    *layout_mount_args(root, spec.host.layout_mount),
                    image,
                ],
            )
        finally:
            searxng.remove(name)


def searxng_args(name: str, network: Sequence[str]) -> list[str]:
    return [
        "run", "-d",
        "--name", name,
        "--label", LABEL,
        *network,
        "--user", "searxng",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", _PIDS_LIMIT,
        *memory_bound_args(),
        "-e", f"SSL_CERT_FILE={_AUTHORITY_PATH}",
        "-v", f"{_AUTHORITY}:{_AUTHORITY_PATH}:ro",
        SEARXNG_IMAGE,
    ]  # fmt: skip
