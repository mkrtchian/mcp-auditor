"""The Jenkins backend's lifecycle: the real Jenkins controller the tools of
hekmon8/Jenkins-server-mcp call through `JENKINS_URL`.

The backend is Jenkins itself (`Dockerfile.jenkins-responder`, the 2.580.2 LTS of the project's
official image pinned by digest), not a responder: its image seeds the job `MyJob`, its first build
and the admin account with a fixed API token at build time. It listens on its default port 8080 as
the image's own user, under the nuisance confinement, memory bound included, with no added
capability. Its state lives in the container only (its home in the anonymous volume Docker fills
from the image at each creation), so a stand-up after its removal starts from the seed. It is a
singleton on a fixed address of its own closed bridge in the RFC 2544 benchmarking range, stood
once and reused across a server's concurrent nuisance runs, reaped by the generic orphan sweep, so
no lock is held across the yield. It carries no witness: a fix check stands its own container of
the same image at another address of the bridge and subnet exported here.

The audited server reaches it as an outbound HTTP request. Its `JENKINS_URL`, `JENKINS_USER` and
`JENKINS_TOKEN` are baked into the run image's own `ENV` (`JENKINS_URL` here), so
`jenkins_server_args` carries no `-e` of its own.

Jenkins takes tens of seconds to start, so `ensure_jenkins_responder` returns once the controller
answers its login page, which it serves only once fully loaded. The container and image keep the
names the responder had.
"""

import subprocess
import threading
import time
from collections.abc import Sequence

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
from evals.cve.planting_base import LABEL, PlantingHost, own_network_args

JENKINS_SERVICE = "jenkins-responder"  # the compose service building the controller image
JENKINS_RESPONDER_IMAGE = f"mcp-auditor-cve-{JENKINS_SERVICE}:local"
JENKINS_RESPONDER_CONTAINER = "mcp-auditor-cve-jenkins-responder"
JENKINS_BRIDGE = "mcp-auditor-cve-jenkins-bridge"  # server <-> Jenkins, static IPs
JENKINS_SUBNET = "198.18.2.0/24"  # RFC 2544: overlaps no other backend's subnet
JENKINS_RESPONDER_IP = "198.18.2.2"
JENKINS_PORT = 8080  # Jenkins's default HTTP port
JENKINS_URL = f"http://{JENKINS_RESPONDER_IP}:{JENKINS_PORT}"
_START_SECONDS = 300.0

# The controller is a singleton, so a caller does not hold this across its yield: a server's
# concurrent runs share it. A plain Lock serialises only the stand-up, since __enter__ and
# __exit__ may run on different worker threads.
JENKINS_LAUNCH_LOCK = threading.Lock()


def singleton_run_args() -> list[str]:
    return [
        "run", "-d",
        "--name", JENKINS_RESPONDER_CONTAINER,
        "--label", LABEL,
        *own_network_args(JENKINS_BRIDGE),
        "--ip", JENKINS_RESPONDER_IP,
        *nuisance_confinement_args(),
        JENKINS_RESPONDER_IMAGE,
    ]  # fmt: skip


def jenkins_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return [
        "run", "-i", "--rm",
        *nuisance_confinement_args(),
        "--name", name,
        "--label", LABEL,
        *own_network_args(JENKINS_BRIDGE),
        *user_args(host.user),
        "-w", host.working_directory,
        image,
        *server_launch,
    ]  # fmt: skip


def ensure_jenkins_responder() -> None:
    ensure_jenkins_image()
    ensure_closed_network(JENKINS_BRIDGE, "--subnet", JENKINS_SUBNET)
    run_args = singleton_run_args()
    if not running_with_launch(JENKINS_RESPONDER_CONTAINER, run_args):
        remove(JENKINS_RESPONDER_CONTAINER)
        _run("docker", *labelled_run_args(run_args))
    wait_until_up(JENKINS_RESPONDER_CONTAINER)


def ensure_jenkins_image() -> None:
    if _run("docker", "image", "inspect", JENKINS_RESPONDER_IMAGE, check=False).returncode != 0:
        dockerfile = image_dockerfile(JENKINS_SERVICE)
        _run(
            "docker", "build", "-t", JENKINS_RESPONDER_IMAGE, "-f", str(dockerfile),
            str(DOCKER_DIRECTORY), timeout=900.0,
        )  # fmt: skip


def wait_until_up(name: str) -> None:
    # Jenkins answers 503 on every page while it loads, so -f fails until it is ready.
    login = f"http://localhost:{JENKINS_PORT}/login"
    probe = ("docker", "exec", name, "curl", "-fs", "-o", "/dev/null", login)
    deadline = time.monotonic() + _START_SECONDS
    while _run(*probe, check=False).returncode != 0:
        if time.monotonic() > deadline:
            raise RuntimeError(f"Jenkins in {name} did not come up within {_START_SECONDS:.0f}s")
        time.sleep(2)


def jenkins_rm(name: str) -> None:
    remove(name)


def _run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


LIFECYCLE = BackendLifecycle(
    "jenkins", JENKINS_LAUNCH_LOCK, ensure_jenkins_responder, jenkins_server_args, jenkins_rm
)
