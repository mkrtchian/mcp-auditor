"""The sshd backend's lifecycle: the real OpenSSH server mcp-ssh's tools reach through the `ssh`
and `scp` clients.

mcp-ssh drives the OpenSSH client against the hosts of its `~/.ssh/config`. The run image writes
the README's section 6 entry, `Host production` reaching `prod.example.com` as `deploy` with the
key `~/.ssh/id_production`. The backend is OpenSSH 10.6p2 built from the portable tarball
(`Dockerfile.mcp-ssh-sshd`), which bakes the public half in `deploy`'s `authorized_keys`, listens
on the default port 22 as that account, takes the README's section 3 server lines on top of the
release's default configuration and serves the sftp subsystem `scp` uses, with the `sample.txt`
the benign download reads. It runs under the nuisance confinement (every capability dropped, no
new privileges, the process bound) with no capability added back, on its own closed labeled bridge
(no route to the host or the Internet) at a fixed address and under the alias `prod.example.com`.

The backend's state lives in its container only (a benign upload writes a file in its home), so
a stand-up after its removal starts from the image. It carries no witness: a fix check stands its
own instance (`stood_sshd`), and so does each launch of the holdout target CVE-2025-9654
(`mcp_ssh_holdout.py`). The run's is a singleton, stood once and reused across a server's
concurrent nuisance runs, reaped by the generic orphan sweep, so no lock is held across the yield.

Every launch mounts the client's `~/.ssh/known_hosts` read-only, the sshd's host keys under the
hostname the client entry names, as the README's section 5 connection test writes it: the release
1.0.3 and 1.0.4 call ssh with no host-key option, so without it they fail on host key
verification. The keys are read with `ssh-keyscan` once the sshd listens, and the file is mode
0644 (section 4), owned by the caller on the nuisance side and by root for the holdout target,
whose launch runs under an account named after a nonce. A short-lived container of the pinned
busybox hands it over, since the host user cannot chown.

This module imports nothing of `mcp_auditor` or `evals.cve.environments`: the re-admission dossier
copies its import closure.
"""

import os
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from evals.cve.backends.lifecycle import BackendLifecycle
from evals.cve.backends.responder import remove
from evals.cve.closed_network import create_closed_network, ensure_closed_network
from evals.cve.docker_paths import DOCKER_DIRECTORY, image_dockerfile
from evals.cve.nuisance.confinement import (
    labelled_run_args,
    nuisance_confinement_args,
    running_with_launch,
    user_args,
)
from evals.cve.planting_base import (
    LABEL,
    UNPRIVILEGED_GID,
    UNPRIVILEGED_UID,
    PlantingHost,
    confinement_args,
    own_network_args,
)
from evals.cve.planting_docker import LAYOUT_HELPER_IMAGE

SSHD_SERVICE = "mcp-ssh-sshd"  # the compose service building the sshd image
SSHD_IMAGE = f"mcp-auditor-cve-{SSHD_SERVICE}:local"
SSHD_CONTAINER = "mcp-auditor-cve-mcp-ssh-sshd"
SSHD_BRIDGE = "mcp-auditor-cve-mcp-ssh-sshd-bridge"
_SSHD_SUBNET = "198.18.8.0/24"  # RFC 2544: overlaps no other backend's subnet
SSHD_IP = "198.18.8.2"
SSH_CONFIG_HOST = "production"  # the Host entry of the run image's ~/.ssh/config
SSHD_ALIAS = "prod.example.com"  # the Hostname that entry names
SSHD_PORT = 22
KNOWN_HOSTS = "/tmp/.ssh/known_hosts"  # the client's ~/.ssh/known_hosts under HOME=/tmp
CALLER = f"{UNPRIVILEGED_UID}:{UNPRIVILEGED_GID}"  # the nuisance launches' user
ROOT = "0:0"
# The run singleton's known_hosts, rewritten at each stand-up: its host keys are baked in the image.
RUN_KNOWN_HOSTS = (
    Path(tempfile.gettempdir()) / f"{LABEL}-mcp-ssh-known-hosts-{os.getuid()}" / "known_hosts"
)
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
        *known_hosts_mount_args(RUN_KNOWN_HOSTS),
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
    _run_known_hosts_directory()
    install_known_hosts(
        RUN_KNOWN_HOSTS, known_hosts_text(scanned_host_keys(SSHD_CONTAINER)), CALLER
    )


def _run_known_hosts_directory() -> None:
    directory = RUN_KNOWN_HOSTS.parent
    directory.mkdir(mode=0o700, exist_ok=True)
    facts = directory.lstat()
    if not directory.is_dir() or directory.is_symlink() or facts.st_uid != os.getuid():
        raise RuntimeError(f"{directory} is not a directory of the invoking user")


def ensure_sshd_image() -> None:
    if _run("docker", "image", "inspect", SSHD_IMAGE, check=False).returncode != 0:
        dockerfile = image_dockerfile(SSHD_SERVICE)
        _run(
            "docker", "build", "-t", SSHD_IMAGE, "-f", str(dockerfile), str(DOCKER_DIRECTORY),
            timeout=900.0,
        )  # fmt: skip


@dataclass(frozen=True)
class StoodSshd:
    network: str
    known_hosts: Path  # the host file holding the client's known_hosts

    def mount_args(self) -> list[str]:
        return known_hosts_mount_args(self.known_hosts)


@contextmanager
def stood_sshd(name: str, owner: str) -> Generator[StoodSshd]:
    """An sshd of its own for one launch, on a closed network of its own, never in a namespace
    holder, whose loopback carries a target's sentinels."""
    ensure_sshd_image()
    network = f"{LABEL}-mcp-ssh-net-{secrets.token_hex(6)}"
    create_closed_network(network)
    directory = Path(tempfile.mkdtemp(prefix=f"{LABEL}-mcp-ssh-known-hosts-"))
    try:
        _run("docker", *sshd_args(name, network))
        known_hosts = directory / "known_hosts"
        install_known_hosts(known_hosts, known_hosts_text(scanned_host_keys(name)), owner)
        yield StoodSshd(network, known_hosts)
    finally:
        remove(name)
        _run("docker", "network", "rm", network, check=False)
        shutil.rmtree(directory, ignore_errors=True)


def sshd_args(name: str, network: str) -> list[str]:
    return [
        "run", "-d",
        "--name", name,
        "--label", LABEL,
        *own_network_args(network),
        "--network-alias", SSHD_ALIAS,
        *confinement_args(),
        SSHD_IMAGE,
    ]  # fmt: skip


def connect_to_network(network: str, container: str) -> None:
    _run("docker", "network", "connect", network, container)


def known_hosts_mount_args(path: Path) -> list[str]:
    return ["-v", f"{path}:{KNOWN_HOSTS}:ro"]


def scanned_host_keys(container: str) -> str:
    # ssh-keyscan (built and installed with the sshd) prints the host keys once sshd accepts
    # connections, and nothing before.
    probe = ("docker", "exec", container, "ssh-keyscan", "-p", str(SSHD_PORT), "127.0.0.1")
    deadline = time.monotonic() + _READY_SECONDS
    while not (scanned := _run(*probe, check=False).stdout).strip():
        if time.monotonic() > deadline:
            raise RuntimeError(f"{container} did not listen within {_READY_SECONDS:.0f}s")
        time.sleep(1)
    return scanned


def known_hosts_text(scanned: str) -> str:
    lines = (line.split() for line in scanned.splitlines() if line and not line.startswith("#"))
    return "".join(f"{SSHD_ALIAS} {' '.join(fields[1:])}\n" for fields in lines)


def install_known_hosts(path: Path, content: str, owner: str) -> None:
    # Staged and renamed, so a launch that mounted the run's file keeps a whole one.
    staged = path.with_name(f".{path.name}-{secrets.token_hex(4)}")
    staged.write_text(content)
    staged.chmod(0o644)
    try:
        _run("docker", *_chown_args(staged, owner))
        os.replace(staged, path)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise


def _chown_args(path: Path, owner: str) -> list[str]:
    return [
        "run", "--rm",
        "--label", LABEL,
        "--network", "none",
        "--cap-drop", "ALL", "--cap-add", "CHOWN",
        "--security-opt", "no-new-privileges",
        "-v", f"{path}:/known_hosts",
        LAYOUT_HELPER_IMAGE,
        "chown", owner, "/known_hosts",
    ]  # fmt: skip


def sshd_rm(name: str) -> None:
    remove(name)


def _run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


LIFECYCLE = BackendLifecycle(
    "mcp_ssh_sshd", SSHD_LAUNCH_LOCK, ensure_sshd, sshd_server_args, sshd_rm
)
