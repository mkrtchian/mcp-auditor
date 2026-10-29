"""The Neo4j backend's lifecycle.

One persistent Neo4j container on a labeled bridge, reachable by container name. The audited
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

from evals.cve_planting import confinement_args
from evals.cve_planting_base import LABEL, PlantingHost
from evals.cve_targets import DOCKER_DIRECTORY
from evals.doris_backend import user_args
from evals.responder_backend import remove

NEO4J_IMAGE = "mcp-auditor-cve-neo4j-backend:local"
NEO4J_BACKEND_DOCKERFILE = DOCKER_DIRECTORY / "Dockerfile.neo4j-backend"
NEO4J_CONTAINER = "mcp-auditor-cve-neo4j"
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
        *confinement_args(),
        "--name", name,
        "--label", LABEL,
        "--network", NEO4J_BRIDGE,
        *user_args(host.user),
        "-w", host.working_directory,
        image,
        *server_launch,
    ]  # fmt: skip


def ensure_neo4j() -> None:
    _ensure_image()
    _ensure_network()
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


def _ensure_network() -> None:
    listed = _run("docker", "network", "ls", "--format", "{{.Name}}", check=False)
    if NEO4J_BRIDGE not in listed.stdout.split():
        _run("docker", "network", "create", "--label", LABEL, NEO4J_BRIDGE)


def _ensure_database() -> None:
    listed = _run("docker", "ps", "--filter", f"name=^{NEO4J_CONTAINER}$", "--format", "{{.Names}}")
    if NEO4J_CONTAINER not in listed.stdout.split():
        remove(NEO4J_CONTAINER)
        _run(
            "docker", "run", "-d",
            "--name", NEO4J_CONTAINER,
            "--label", LABEL,
            "--network", NEO4J_BRIDGE,
            *_DATABASE_ENVIRONMENT,
            NEO4J_IMAGE,
        )  # fmt: skip
    _wait_until_ready()


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
