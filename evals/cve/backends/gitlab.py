"""The GitLab backend: GitLab CE itself, stood for each launch of `npm:@zereight/mcp-gitlab`.

The image (`Dockerfile.gitlab-backend`) is GitLab CE 19.5.5, the stable release on 2026-11-13,
since the server's documentation and tests at 2.1.38 name no GitLab version, with the GitLab
Runner 19.5.3 binary added, the latest patch of the 19.5 line (no 19.5.5 Runner exists). The
settings are those of GitLab's "Running GitLab in a memory-constrained environment" page, passed
through `GITLAB_OMNIBUS_CONFIG`, with `external_url` on `gitlab.example.com`, the host the run
image's `GITLAB_API_URL` names, which the container takes as its hostname and network alias.
`--shm-size 256m` is the size GitLab's Docker installation documents.

The play, retry and cancel tools change job state for good, so each launch stands its own GitLab
on its own closed network and removes both with its server. The stand-up waits for Omnibus's
`gitlab Reconfigured!` and for `/-/readiness`, which answers before the reconfigure ends, then
runs the seed of `evals.cve.backends.gitlab_seed`, starts the registered Runner inside the GitLab
container and waits until the pipeline's non-manual jobs have finished. Measured on three
stand-ups: ready in about two and a half minutes, seeded about forty seconds later, a peak near
3.8 GiB under the 4 GiB memory bound.

GitLab's Omnibus image runs its services as root and as their own accounts, so the backend cannot
take the server's confinement: it runs under no new privileges with every capability dropped but
the six Omnibus was measured to need (CHOWN, DAC_OVERRIDE and FOWNER for its data directories,
SETGID and SETUID to switch accounts, KILL for runit to signal them), a process bound of 4096
(its peak is about 275), and the memory bound. The server keeps the confinement and
takes the token the seed created with `-e`, which wins over the README value its image bakes.
"""

import secrets
import subprocess
import time
from collections.abc import Callable, Generator, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass

from evals.cve.backends.gitlab_seed import GITLAB_TOKEN, SEED_PROJECTS, START_RUNNER, WAIT_FOR_JOBS
from evals.cve.backends.lifecycle import LaunchedServerArgs, PerLaunchBackend
from evals.cve.closed_network import create_closed_network
from evals.cve.docker_paths import DOCKER_DIRECTORY, image_dockerfile
from evals.cve.nuisance.confinement import user_args
from evals.cve.planting_base import (
    LABEL,
    PlantingHost,
    confinement_args,
    memory_bound_args,
    own_network_args,
)

GITLAB_SERVICE = "gitlab-backend"  # the compose service building the GitLab CE image
GITLAB_IMAGE = f"mcp-auditor-cve-{GITLAB_SERVICE}:local"
GITLAB_NETWORK = f"{LABEL}-gitlab-net"  # the prefix of each launch's closed network
GITLAB_HOST = "gitlab.example.com"
GITLAB_CAPABILITIES = ("CHOWN", "DAC_OVERRIDE", "FOWNER", "KILL", "SETGID", "SETUID")
GITLAB_PIDS_LIMIT = "4096"
GITLAB_SHM_SIZE = "256m"
_READY_SECONDS = 900.0
_SEED_SECONDS = 900.0
_READINESS = "http://127.0.0.1/-/readiness"
_RECONFIGURED = "gitlab Reconfigured!"
_RECONFIGURE_FAILED = "There was an error running gitlab-ctl reconfigure"

OMNIBUS_CONFIG = f"""external_url 'http://{GITLAB_HOST}'
puma['worker_processes'] = 0
sidekiq['concurrency'] = 10
prometheus_monitoring['enable'] = false
gitlab_rails['env'] = {{ 'MALLOC_CONF' => 'dirty_decay_ms:1000,muzzy_decay_ms:1000' }}
gitaly['configuration'] = {{ concurrency: [ {{ 'rpc' => "/gitaly.SmartHTTPService/PostReceivePack", 'max_per_repo' => 3 }}, {{ 'rpc' => "/gitaly.SSHService/SSHUploadPack", 'max_per_repo' => 3 }} ] }}
gitaly['env'] = {{ 'MALLOC_CONF' => 'dirty_decay_ms:1000,muzzy_decay_ms:1000', 'GITALY_COMMAND_SPAWN_MAX_PARALLEL' => '2' }}
alertmanager['enable'] = false
gitlab_exporter['enable'] = false
gitlab_kas['enable'] = false
node_exporter['enable'] = false
postgres_exporter['enable'] = false
prometheus['enable'] = false
puma['exporter_enabled'] = false
redis_exporter['enable'] = false
sidekiq['metrics_enabled'] = false
"""  # noqa: E501


@dataclass(frozen=True)
class StoodGitLab:
    network: str
    token: str


type GitLabStand = Callable[[str], AbstractContextManager[StoodGitLab]]  # backend name -> GitLab


def gitlab_launch(stand: GitLabStand, remove: Callable[[str], None]) -> LaunchedServerArgs:
    @contextmanager
    def launch(
        name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
    ) -> Generator[list[str]]:
        with stand(f"{name}-gitlab") as gitlab:
            try:
                yield server_run_args(name, image, host, server_launch, gitlab)
            finally:
                remove(name)

    return launch


def server_run_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str], gitlab: StoodGitLab
) -> list[str]:
    return [
        "run", "-i", "--rm",
        *confinement_args(),
        "--name", name,
        "--label", LABEL,
        *own_network_args(gitlab.network),
        "-e", f"GITLAB_PERSONAL_ACCESS_TOKEN={gitlab.token}",
        *user_args(host.user),
        "-w", host.working_directory,
        image,
        *server_launch,
    ]  # fmt: skip


@contextmanager
def stood_gitlab(name: str) -> Generator[StoodGitLab]:
    ensure_gitlab_image()
    network = f"{GITLAB_NETWORK}-{secrets.token_hex(6)}"
    create_closed_network(network)
    try:
        _run("docker", *gitlab_run_args(name, network))
        wait_until_ready(name)
        seed(name)
        yield StoodGitLab(network, GITLAB_TOKEN)
    finally:
        remove(name)
        _run("docker", "network", "rm", network, check=False)


def gitlab_run_args(name: str, network: str) -> list[str]:
    capabilities = (arg for capability in GITLAB_CAPABILITIES for arg in ("--cap-add", capability))
    return [
        "run", "-d",
        "--name", name,
        "--label", LABEL,
        "--hostname", GITLAB_HOST,
        *own_network_args(network),
        "--network-alias", GITLAB_HOST,
        "--shm-size", GITLAB_SHM_SIZE,
        "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL",
        *capabilities,
        "--pids-limit", GITLAB_PIDS_LIMIT,
        *memory_bound_args(),
        "-e", f"GITLAB_OMNIBUS_CONFIG={OMNIBUS_CONFIG}",
        GITLAB_IMAGE,
    ]  # fmt: skip


def ensure_gitlab_image() -> None:
    if _run("docker", "image", "inspect", GITLAB_IMAGE, check=False).returncode != 0:
        dockerfile = image_dockerfile(GITLAB_SERVICE)
        _run(
            "docker", "build", "-t", GITLAB_IMAGE, "-f", str(dockerfile), str(DOCKER_DIRECTORY),
            timeout=1800.0,
        )  # fmt: skip


def wait_until_ready(name: str) -> None:
    deadline = time.monotonic() + _READY_SECONDS
    while not _ready(name):
        if time.monotonic() > deadline:
            raise RuntimeError(f"GitLab in {name} was not ready within {_READY_SECONDS:.0f}s")
        time.sleep(3)


def _ready(name: str) -> bool:
    # /-/readiness answers mid-reconfigure, before Omnibus restarts Workhorse and NGINX, so the
    # log line that ends the reconfigure is awaited too.
    logs = _run("docker", "logs", name, check=False)
    output = logs.stdout + logs.stderr
    if _RECONFIGURE_FAILED in output:
        raise RuntimeError(f"GitLab in {name} failed to reconfigure")
    status = _run("docker", "inspect", "-f", "{{.State.Status}}", name, check=False)
    if status.stdout.strip() != "running":
        raise RuntimeError(f"GitLab in {name} stopped before it was ready")
    readiness = _run(
        "docker", "exec", name, "curl", "-sf", "-o", "/dev/null", _READINESS, check=False
    )
    return _RECONFIGURED in output and readiness.returncode == 0


def seed(name: str) -> None:
    _seed_script(name, SEED_PROJECTS)
    _run("docker", "exec", "-d", name, "bash", "-c", START_RUNNER)
    _seed_script(name, WAIT_FOR_JOBS)


def _seed_script(name: str, script: str) -> None:
    _run(
        "docker", "exec", "-i", "-e", f"SEED_TOKEN={GITLAB_TOKEN}", name, "bash", "-s",
        script=script, timeout=_SEED_SECONDS,
    )  # fmt: skip


def remove(name: str) -> None:
    _run("docker", "rm", "-f", "-v", name, check=False)


def _run(
    *args: str, check: bool = True, timeout: float = 120.0, script: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args), check=check, capture_output=True, text=True, timeout=timeout, input=script
    )


LIFECYCLE = PerLaunchBackend("gitlab", gitlab_launch(stood_gitlab, remove))
