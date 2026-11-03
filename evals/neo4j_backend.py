"""The Neo4j backend's lifecycle.

One persistent Neo4j container on a closed labeled bridge (no route to the host or the Internet),
reachable by container name. The audited
mcp-neo4j-cypher reaches its database over Bolt, so the container behind `NEO4J_CONTAINER` is the
database its run image's `NEO4J_URI` names. APOC is installed and its `apoc.load.*` procedures are
unrestricted while file import is off, so a patched server's read-only gate is what stands between
the auditor and a server-side request through `apoc.load.*`. Nothing is planted.

A caller drives this through `ensure_neo4j`, `neo4j_server_args`, `neo4j_rm` and
`NEO4J_LAUNCH_LOCK`. The container is stood once and left running, reused across exercises; the
generic orphan sweep reaps anything labelled `mcp-auditor-cve`. Its image is built here from
`Dockerfile.neo4j-backend` when absent, the digest pin living in that file.
"""

import subprocess
import threading
import time
from collections.abc import Sequence

from evals.backend_lifecycle import BackendLifecycle
from evals.closed_network import ensure_closed_network
from evals.cve_planting_base import LABEL, PlantingHost, own_network_args
from evals.docker_paths import DOCKER_DIRECTORY
from evals.nuisance_confinement import (
    labelled_run_args,
    memory_bound_args,
    nuisance_confinement_args,
    running_with_launch,
    user_args,
)
from evals.responder_backend import remove

NEO4J_IMAGE = "mcp-auditor-cve-neo4j-backend:local"
NEO4J_BACKEND_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.neo4j-backend"
NEO4J_CONTAINER = "mcp-auditor-cve-neo4j"
NEO4J_HOST = "neo4j"  # the database's alias on NEO4J_BRIDGE
NEO4J_BRIDGE = "mcp-auditor-cve-neo4j-bridge"  # server <-> database, name resolution
_PASSWORD = "testpassword"  # Neo4j rejects passwords under 8 characters
_READY_DEADLINE = 120.0

# A plain Lock serialising only the stand-up, not held across the yield: a server's concurrent
# runs share the one database. Plain rather than RLock because __enter__ and __exit__ may run on
# different worker threads.
NEO4J_LAUNCH_LOCK = threading.Lock()

_DATABASE_ENVIRONMENT = [
    "-e", f"NEO4J_AUTH=neo4j/{_PASSWORD}",
    "-e", "NEO4J_apoc_import_file_enabled=false",  # the request goes through apoc.load.*
    "-e", "NEO4J_dbms_security_procedures_unrestricted=apoc.*",
    "-e", "NEO4J_dbms_security_procedures_allowlist=apoc.*",
]  # fmt: skip


def neo4j_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return [
        "run", "-i", "--rm",
        *nuisance_confinement_args(),
        "--name", name,
        "--label", LABEL,
        *own_network_args(NEO4J_BRIDGE),
        *user_args(host.user),
        "-w", host.working_directory,
        image,
        *server_launch,
    ]  # fmt: skip


def ensure_neo4j() -> None:
    _ensure_image()
    ensure_closed_network(NEO4J_BRIDGE)
    _ensure_database()


def neo4j_rm(name: str) -> None:
    remove(name)


def _ensure_image() -> None:
    present = _run("docker", "image", "inspect", NEO4J_IMAGE, check=False)
    if present.returncode != 0:
        _run(
            "docker", "build", "-t", NEO4J_IMAGE, "-f", str(NEO4J_BACKEND_DOCKERFILE),
            str(DOCKER_DIRECTORY), timeout=600.0,
        )  # fmt: skip


def _ensure_database() -> None:
    if not running_with_launch(NEO4J_CONTAINER, database_run_args()):
        remove(NEO4J_CONTAINER)
        _run("docker", *labelled_run_args(database_run_args()))
    _wait_until_ready()


def database_run_args() -> list[str]:
    return [
        "run", "-d",
        "--name", NEO4J_CONTAINER,
        "--label", LABEL,
        *own_network_args(NEO4J_BRIDGE),
        "--network-alias", NEO4J_HOST,
        *memory_bound_args(),
        *_DATABASE_ENVIRONMENT,
        NEO4J_IMAGE,
    ]  # fmt: skip


def _wait_until_ready() -> None:
    deadline = time.monotonic() + _READY_DEADLINE
    while time.monotonic() < deadline:
        if _answers_a_query():
            return
        time.sleep(2)
    raise RuntimeError("Neo4j did not become ready")


def _answers_a_query() -> bool:
    answered = _run(
        "docker", "exec", NEO4J_CONTAINER,
        "cypher-shell", "-u", "neo4j", "-p", _PASSWORD, "RETURN 1",
        check=False,
    )  # fmt: skip
    return answered.returncode == 0


def _run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


LIFECYCLE = BackendLifecycle("neo4j", NEO4J_LAUNCH_LOCK, ensure_neo4j, neo4j_server_args, neo4j_rm)
