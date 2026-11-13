"""The Kubernetes backend: an upstream control plane, stood for each launch of a kubectl server.

The image (`Dockerfile.kube-control-plane`) is upstream Kubernetes v1.37.2, the stable release on
2026-11-13, with etcd 3.7.0, the version that release names, since kubectl-mcp-server's
documentation names no distribution or version. Its entrypoint runs kubeadm's file phases with the
container's own address as the advertise address, starts etcd, kube-apiserver,
kube-controller-manager and kube-scheduler with the command lines of the manifests kubeadm wrote,
and creates the `kubeadm:cluster-admins` binding once `/readyz` answers, so the certificates and
kubeconfigs are generated per launch and never expire inside an image. No kubelet runs, since it
needs a container runtime and privileges the confinement does not give: the cluster has no node.

The control plane runs in its own network namespace, on a per-launch closed network, never in a
namespace holder: the API server can be made to fetch addresses (a webhook, an aggregated API), and
a holder's loopback carries a target's link-local sentinels. The server reaches it by the address
`admin.conf` names, so no name lookup is involved. `admin.conf` is read out of the container into a
host file of mode 0644, which the server's unprivileged account reads at kubectl's default path
under `HOME=/tmp`.

The control plane runs as the unprivileged account under the detection suite's confinement (every
capability dropped, no new privileges, the process bound) with no capability added: measured on
2026-11-13, it is ready in about five seconds and peaks at 89 threads under `get pods`,
`get namespaces` and `get nodes`, well under the bound of 256, and holds about 410 MiB. As a
nuisance backend it also takes the memory bound. The control plane's state changes with the
auditor's calls, so each launch stands its own and removes it with its server.

This module imports nothing of `mcp_auditor`: the re-admission dossier copies its import closure.
"""

import secrets
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Generator, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path

from evals.cve.backends.lifecycle import LaunchedServerArgs, PerLaunchBackend
from evals.cve.closed_network import create_closed_network
from evals.cve.docker_paths import DOCKER_DIRECTORY, image_dockerfile
from evals.cve.nuisance.confinement import memory_bound_args, nuisance_confinement_args, user_args
from evals.cve.planting_base import (
    LABEL,
    UNPRIVILEGED_GID,
    UNPRIVILEGED_UID,
    PlantingHost,
    confinement_args,
    own_network_args,
    unprivileged_user_args,
)

CONTROL_PLANE_SERVICE = "kube-control-plane"  # the compose service building the image
CONTROL_PLANE_IMAGE = f"mcp-auditor-cve-{CONTROL_PLANE_SERVICE}:local"
CONTROL_PLANE_NETWORK = f"{LABEL}-kube-net"  # the prefix of each launch's closed network
KUBECONFIG = "/tmp/.kube/config"  # kubectl's default path under HOME=/tmp
READY_LINE = "control plane ready"  # the entrypoint's last line once the binding exists
_ADMIN_CONF = "/etc/kubernetes/admin.conf"
_OWNED_TMPFS = f"uid={UNPRIVILEGED_UID},gid={UNPRIVILEGED_GID}"
_READY_SECONDS = 180.0


@dataclass(frozen=True)
class StoodControlPlane:
    network: str
    kubeconfig: Path  # the host file holding admin.conf

    def mount_args(self) -> list[str]:
        return ["-v", f"{self.kubeconfig}:{KUBECONFIG}:ro"]


# (control plane name, memory bound) -> the stood control plane
type ControlPlaneStand = Callable[[str, Sequence[str]], AbstractContextManager[StoodControlPlane]]


def control_plane_launch(
    stand: ControlPlaneStand, remove: Callable[[str], None]
) -> LaunchedServerArgs:
    @contextmanager
    def launch(
        name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
    ) -> Generator[list[str]]:
        with stand(f"{name}-kube", memory_bound_args()) as control_plane:
            try:
                yield server_run_args(name, image, host, server_launch, control_plane)
            finally:
                remove(name)

    return launch


def server_run_args(
    name: str,
    image: str,
    host: PlantingHost,
    server_launch: Sequence[str],
    control_plane: StoodControlPlane,
) -> list[str]:
    return [
        "run", "-i", "--rm",
        *nuisance_confinement_args(),
        "--name", name,
        "--label", LABEL,
        *own_network_args(control_plane.network),
        *control_plane.mount_args(),
        *user_args(host.user),
        "-w", host.working_directory,
        image,
        *server_launch,
    ]  # fmt: skip


@contextmanager
def stood_control_plane(
    name: str, memory_bound: Sequence[str] = ()
) -> Generator[StoodControlPlane]:
    ensure_control_plane_image()
    network = f"{CONTROL_PLANE_NETWORK}-{secrets.token_hex(6)}"
    create_closed_network(network)
    directory = Path(tempfile.mkdtemp(prefix=f"{LABEL}-kubeconfig-"))
    try:
        _run("docker", *control_plane_run_args(name, network, memory_bound))
        wait_until_ready(name)
        kubeconfig = directory / "config"
        kubeconfig.write_text(_run("docker", "exec", name, "cat", _ADMIN_CONF).stdout)
        kubeconfig.chmod(0o644)
        yield StoodControlPlane(network, kubeconfig)
    finally:
        remove(name)
        _run("docker", "network", "rm", network, check=False)
        shutil.rmtree(directory, ignore_errors=True)


def control_plane_run_args(name: str, network: str, memory_bound: Sequence[str]) -> list[str]:
    return [
        "run", "-d",
        "--name", name,
        "--label", LABEL,
        *own_network_args(network),
        *confinement_args(),
        *memory_bound,
        *unprivileged_user_args(),
        # kubeadm writes the certificates, kubeconfigs and manifests, and etcd its data, per launch.
        "--tmpfs", f"/etc/kubernetes:{_OWNED_TMPFS},mode=0755",
        "--tmpfs", f"/var/lib/etcd:{_OWNED_TMPFS},mode=0700",
        CONTROL_PLANE_IMAGE,
    ]  # fmt: skip


def connect_to_network(network: str, container: str) -> None:
    _run("docker", "network", "connect", network, container)


def ensure_control_plane_image() -> None:
    if _run("docker", "image", "inspect", CONTROL_PLANE_IMAGE, check=False).returncode != 0:
        dockerfile = image_dockerfile(CONTROL_PLANE_SERVICE)
        _run(
            "docker", "build", "-t", CONTROL_PLANE_IMAGE, "-f", str(dockerfile),
            str(DOCKER_DIRECTORY), timeout=900.0,
        )  # fmt: skip


def wait_until_ready(name: str) -> None:
    deadline = time.monotonic() + _READY_SECONDS
    while not _ready(name):
        if time.monotonic() > deadline:
            raise RuntimeError(
                f"the control plane {name} was not ready within {_READY_SECONDS:.0f}s"
            )
        time.sleep(0.5)


def _ready(name: str) -> bool:
    logs = _run("docker", "logs", name, check=False)
    if READY_LINE in logs.stdout:
        return True
    status = _run("docker", "inspect", "-f", "{{.State.Status}}", name, check=False)
    if status.stdout.strip() != "running":
        raise RuntimeError(f"the control plane {name} stopped before it was ready: {logs.stderr}")
    return False


def remove(name: str) -> None:
    _run("docker", "rm", "-f", "-v", name, check=False)


def _run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


LIFECYCLE = PerLaunchBackend("kubernetes", control_plane_launch(stood_control_plane, remove))
