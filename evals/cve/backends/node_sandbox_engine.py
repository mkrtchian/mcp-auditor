"""The node sandbox engine: the Docker Engine API v1.41 stand-in node-code-sandbox-mcp's Docker CLI
speaks to, in a container of its own.

The server runs the real Docker CLI, which speaks to the daemon on `/var/run/docker.sock`. The
daemon cannot run under the confinement, so a responder answers at the Engine API
(`Dockerfile.node-sandbox-engine`, `FROM node:lts-slim`, the image the server requests by default),
and runs each exec'd command and extracts each archive upload in that image, as a real daemon runs
them in a `node:lts-slim` container. The responder keeps a single pending exec and one map of the
containers it holds, and the auditor's calls change both, so the engine is stood for each launch
and removed with it.

Each launch makes a host directory, mounted at the engine's `/run`, where the engine's entrypoint
opens its socket and gives it mode 0666, so the server's unprivileged account connects. The server
mounts that socket at `/var/run/docker.sock`, the launch the server's README documents, so no
`DOCKER_HOST` is set. Both containers run with no network. The engine runs as root inside its
container, as the sandbox of a real daemon does, under the confinement (every capability dropped,
no new privileges, the process bound, the memory bound), with no capability added back.
The directory is made writable by every account, since that root holds no capability that would
let it write into a directory the host's user owns.
"""

import shutil
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable, Generator, Sequence
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path

from evals.cve.backends.lifecycle import LaunchedServerArgs, PerLaunchBackend
from evals.cve.docker_paths import DOCKER_DIRECTORY, image_dockerfile
from evals.cve.nuisance.confinement import user_args
from evals.cve.planting_base import LABEL, PlantingHost, confinement_args, no_network_args

ENGINE_SERVICE = "node-sandbox-engine"  # the compose service building the engine image
ENGINE_IMAGE = f"mcp-auditor-cve-{ENGINE_SERVICE}:local"
ENGINE_NETWORK = "none"  # the engine and its server join no network
ENGINE_SOCKET_DIRECTORY = "/run"  # /var/run in the engine's Debian base
DOCKER_SOCKET = "/var/run/docker.sock"  # the Docker CLI's default socket in the server
_SOCKET_NAME = "docker.sock"
_SOCKET_MODE = 0o666
_READY_SECONDS = 30.0

type EngineStand = Callable[[str], AbstractContextManager[Path]]  # engine name -> socket


def engine_launch(stand: EngineStand, remove: Callable[[str], None]) -> LaunchedServerArgs:
    @contextmanager
    def launch(
        name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
    ) -> Generator[list[str]]:
        with stand(f"{name}-engine") as socket:
            try:
                yield server_run_args(name, image, host, server_launch, socket)
            finally:
                remove(name)

    return launch


def server_run_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str], socket: Path
) -> list[str]:
    return [
        "run", "-i", "--rm",
        *confinement_args(),
        "--name", name,
        "--label", LABEL,
        *no_network_args(),
        *socket_mount_args(socket),
        *user_args(host.user),
        "-w", host.working_directory,
        image,
        *server_launch,
    ]  # fmt: skip


def socket_mount_args(socket: Path) -> list[str]:
    return ["-v", f"{socket}:{DOCKER_SOCKET}"]


@contextmanager
def stood_engine(name: str) -> Generator[Path]:
    ensure_engine_image()
    directory = Path(tempfile.mkdtemp(prefix=f"{LABEL}-{ENGINE_SERVICE}-"))
    try:
        directory.chmod(0o777)
        _run("docker", *engine_run_args(name, directory))
        socket = directory / _SOCKET_NAME
        _wait_for_socket(socket)
        yield socket
    finally:
        remove(name)
        # Sandboxed code runs as the engine's root and may leave a root-owned tree in the
        # directory, which the host's user cannot empty: what it cannot remove stays in the
        # temporary directory.
        shutil.rmtree(directory, ignore_errors=True)


def engine_run_args(name: str, directory: Path) -> list[str]:
    return [
        "run", "-d",
        "--name", name,
        "--label", LABEL,
        *no_network_args(),
        *confinement_args(),
        "-v", f"{directory}:{ENGINE_SOCKET_DIRECTORY}",
        ENGINE_IMAGE,
    ]  # fmt: skip


def ensure_engine_image() -> None:
    if _run("docker", "image", "inspect", ENGINE_IMAGE, check=False).returncode != 0:
        dockerfile = image_dockerfile(ENGINE_SERVICE)
        _run(
            "docker", "build", "-t", ENGINE_IMAGE, "-f", str(dockerfile), str(DOCKER_DIRECTORY),
            timeout=900.0,
        )  # fmt: skip


def remove(name: str) -> None:
    _run("docker", "rm", "-f", "-v", name, check=False)


def _wait_for_socket(socket: Path) -> None:
    deadline = time.monotonic() + _READY_SECONDS
    while not _is_open(socket):
        if time.monotonic() > deadline:
            raise RuntimeError(f"the node sandbox engine did not open {socket} in time")
        time.sleep(0.1)


def _is_open(socket: Path) -> bool:
    try:
        mode = socket.stat().st_mode
    except FileNotFoundError:
        return False
    return stat.S_ISSOCK(mode) and stat.S_IMODE(mode) == _SOCKET_MODE


def _run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


LIFECYCLE = PerLaunchBackend("node_sandbox_engine", engine_launch(stood_engine, remove))
