"""The sshd backend's lifecycle: the real OpenSSH server mcp-ssh's tools reach through the `ssh`
and `scp` clients.

mcp-ssh drives the OpenSSH client against the hosts of its `~/.ssh/config`. The run image writes
that config with one host, `sshhost`, and the private half of an ed25519 key. The backend is
Debian bookworm's `openssh-server` (`Dockerfile.mcp-ssh-sshd`), which bakes the public half in
its account's `authorized_keys`, listens on 2222 as that unprivileged account, takes keys only
and serves the sftp subsystem `scp` uses, with the `sample.txt` the benign download reads. It
runs under the nuisance confinement with no added capability, on its own closed labeled bridge
(no route to the host or the Internet) at a fixed address and under the alias `sshhost`.

The backend's state lives in its container only (a benign upload writes a file in its home), so
a stand-up after its removal starts from the image. It carries no witness: a fix check stands its
own instance. It is a singleton, stood once and reused across a server's concurrent nuisance
runs, reaped by the generic orphan sweep, so no lock is held across the yield.
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

SSHD_SERVICE = "mcp-ssh-sshd"  # the compose service building the sshd image
SSHD_IMAGE = f"mcp-auditor-cve-{SSHD_SERVICE}:local"
SSHD_CONTAINER = "mcp-auditor-cve-mcp-ssh-sshd"
SSHD_BRIDGE = "mcp-auditor-cve-mcp-ssh-sshd-bridge"
_SSHD_SUBNET = "198.18.8.0/24"  # RFC 2544: overlaps no other backend's subnet
SSHD_IP = "198.18.8.2"
SSHD_ALIAS = "sshhost"  # the host the run image's ~/.ssh/config names
SSHD_PORT = 2222
_READY_SECONDS = 60.0

# The sshd is a singleton, so a caller does not hold this across its yield: a server's concurrent
# runs share it. A plain Lock serialises only the stand-up, since __enter__ and __exit__ may run on
# different worker threads.
SSHD_LAUNCH_LOCK = threading.Lock()


def singleton_run_args() -> list[str]:
    return [
        "run", "-d",
        "--name", SSHD_CONTAINER,
        "--label", LABEL,
        *own_network_args(SSHD_BRIDGE),
        "--ip", SSHD_IP,
        "--network-alias", SSHD_ALIAS,
        *nuisance_confinement_args(),
        SSHD_IMAGE,
    ]  # fmt: skip


def sshd_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return [
        "run", "-i", "--rm",
        *nuisance_confinement_args(),
        "--name", name,
        "--label", LABEL,
        *own_network_args(SSHD_BRIDGE),
        *user_args(host.user),
        "-w", host.working_directory,
        image,
        *server_launch,
    ]  # fmt: skip


def ensure_sshd() -> None:
    ensure_sshd_image()
    ensure_closed_network(SSHD_BRIDGE, "--subnet", _SSHD_SUBNET)
    run_args = singleton_run_args()
    if not running_with_launch(SSHD_CONTAINER, run_args):
        remove(SSHD_CONTAINER)
        _run("docker", *labelled_run_args(run_args))
    _wait_until_listening()


def ensure_sshd_image() -> None:
    if _run("docker", "image", "inspect", SSHD_IMAGE, check=False).returncode != 0:
        dockerfile = image_dockerfile(SSHD_SERVICE)
        _run(
            "docker", "build", "-t", SSHD_IMAGE, "-f", str(dockerfile), str(DOCKER_DIRECTORY),
            timeout=900.0,
        )  # fmt: skip


def _wait_until_listening() -> None:
    # ssh-keyscan (from the openssh-client openssh-server depends on) prints the host key once
    # sshd accepts connections, and nothing before.
    probe = ("docker", "exec", SSHD_CONTAINER, "ssh-keyscan", "-p", str(SSHD_PORT), "127.0.0.1")
    deadline = time.monotonic() + _READY_SECONDS
    while not _run(*probe, check=False).stdout.strip():
        if time.monotonic() > deadline:
            raise RuntimeError(f"{SSHD_CONTAINER} did not listen within {_READY_SECONDS:.0f}s")
        time.sleep(1)


def sshd_rm(name: str) -> None:
    remove(name)


def _run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


LIFECYCLE = BackendLifecycle(
    "mcp_ssh_sshd", SSHD_LAUNCH_LOCK, ensure_sshd, sshd_server_args, sshd_rm
)
