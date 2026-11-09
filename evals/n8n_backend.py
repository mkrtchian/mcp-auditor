"""The n8n backend's lifecycle: the real n8n instance a patched n8n-mcp points N8N_API_URL at.

The backend is n8n itself (`Dockerfile.n8n-instance`, the image n8n distributes pinned by
digest), not a responder: it serves the public API (`/api/v1/...`) and the webhooks of its active
workflows. It is a singleton on a fixed public-range (TEST-NET-1) address of its own closed
bridge, so n8n-mcp's default `strict` SSRF gate, which since 2.50.2 also covers N8N_API_URL,
passes it without `WEBHOOK_SECURITY_MODE` being changed. It runs under the nuisance confinement,
memory bound included, with no added capability (n8n listens on 5678, its default port). Stood
once and reused across a server's concurrent nuisance runs, it is reaped by the generic orphan
sweep, so no lock is held across the yield.

At each stand-up `ensure_n8n_instance` runs the image's `/opt/n8n-setup/owner.mjs` through
`docker exec`: on the instance's first start it sets up the owner account, has n8n issue an API
key and activates the documentation's webhook example; on every start it imports the Form node
example again when a benign call deleted it, and prints the key, which it keeps in the instance's
data directory, so a reused singleton hands every launch the same key. `n8n_server_args` passes
N8N_API_URL and that key to the server as `-e` options: the run image bakes no backend
environment.

This is the nuisance run's backend; `n8n_instance_backend` is the holdout target's.
"""

import subprocess
import threading
from collections.abc import Sequence
from dataclasses import dataclass

from evals.backend_lifecycle import BackendLifecycle
from evals.closed_network import ensure_closed_network
from evals.cve_planting_base import LABEL, PlantingHost, own_network_args
from evals.docker_paths import DOCKER_DIRECTORY, image_dockerfile
from evals.nuisance_confinement import (
    labelled_run_args,
    nuisance_confinement_args,
    running_with_launch,
    user_args,
)
from evals.responder_backend import remove

N8N_SERVICE = "n8n-instance"  # the compose service building the instance image
N8N_IMAGE = f"mcp-auditor-cve-{N8N_SERVICE}:local"
N8N_CONTAINER = "mcp-auditor-cve-n8n-instance"
N8N_BRIDGE = "mcp-auditor-cve-n8n-bridge"
_N8N_SUBNET = "192.0.2.0/24"  # TEST-NET-1: overlaps no other backend's subnet
N8N_IP = "192.0.2.2"
N8N_API_URL = f"http://{N8N_IP}:5678/"

# The instance is a singleton, so a caller does not hold this across its yield: a server's
# concurrent runs share it. A plain Lock serialises only the stand-up, since __enter__ and
# __exit__ may run on different worker threads.
N8N_LAUNCH_LOCK = threading.Lock()


@dataclass
class IssuedKey:
    value: str = ""  # empty until ensure_n8n_instance has run


_ISSUED_KEY = IssuedKey()


def singleton_run_args() -> list[str]:
    return [
        "run", "-d",
        "--name", N8N_CONTAINER,
        "--label", LABEL,
        *own_network_args(N8N_BRIDGE),
        "--ip", N8N_IP,
        *nuisance_confinement_args(),
        N8N_IMAGE,
    ]  # fmt: skip


def n8n_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return [
        "run", "-i", "--rm",
        *nuisance_confinement_args(),
        "--name", name,
        "--label", LABEL,
        *own_network_args(N8N_BRIDGE),
        "-e", f"N8N_API_URL={N8N_API_URL}",
        "-e", f"N8N_API_KEY={_ISSUED_KEY.value}",
        *user_args(host.user),
        "-w", host.working_directory,
        image,
        *server_launch,
    ]  # fmt: skip


def ensure_n8n_instance() -> None:
    _ensure_image()
    ensure_closed_network(N8N_BRIDGE, "--subnet", _N8N_SUBNET)
    run_args = singleton_run_args()
    if not running_with_launch(N8N_CONTAINER, run_args):
        remove(N8N_CONTAINER)
        _run("docker", *labelled_run_args(run_args))
    set_up = ("docker", "exec", N8N_CONTAINER, "node", "/opt/n8n-setup/owner.mjs")
    _ISSUED_KEY.value = _run(*set_up, timeout=300.0).stdout.strip()


def _ensure_image() -> None:
    if _run("docker", "image", "inspect", N8N_IMAGE, check=False).returncode != 0:
        dockerfile = image_dockerfile(N8N_SERVICE)
        _run(
            "docker", "build", "-t", N8N_IMAGE, "-f", str(dockerfile), str(DOCKER_DIRECTORY),
            timeout=900.0,
        )  # fmt: skip


def n8n_rm(name: str) -> None:
    remove(name)


def _run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


LIFECYCLE = BackendLifecycle("n8n", N8N_LAUNCH_LOCK, ensure_n8n_instance, n8n_server_args, n8n_rm)
