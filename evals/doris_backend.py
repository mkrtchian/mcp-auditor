"""The Doris target's persistent cluster backend (CVE-2025-66335).

The flaw's internal fetch runs on the Doris backend (its `http()` TVF), not on the server
container, so the exploit needs a live Doris FE+BE cluster and a sentinel the backend can reach
at the fixed metadata IP the payload fetches. The cluster is heavy (a JVM front-end and
back-end) and slow to stand up, so it is provisioned once and reused across every exercise; only
the per-launch sentinels are stood and torn down per run, inside `doris_db_env`.

This module owns that backend's lifecycle, kept apart from the launch-construction concern of
`cve_environments`: ensuring the cluster is up and query-ready, standing a sentinel, and the
thin `docker` wrappers underneath. `doris_db_env` (the builder, alongside the others in
`cve_environments`) drives this through `ensure_doris`, `start_doris_sentinel`, `doris_rm` and
`DORIS_LAUNCH_LOCK`, and wires `DORIS_CONTAINER`/`DORIS_BRIDGE`/`DORIS_DB` into the launch.

The persistent cluster and its two networks are left running on purpose (reused across
exercises); the generic orphan sweep documented in `cve_environments` reaps anything labelled
`mcp-auditor-cve`, the sentinels included.
"""

import subprocess
import threading
import time
from contextlib import suppress
from uuid import uuid4

from evals.cve_planting import confinement_args
from evals.cve_planting_base import LABEL, SENTINEL_IMAGE, SentinelIntent

_DORIS_IMAGE = "apache/doris:all-in-one-4.1.3"
# a throwaway MySQL-protocol client for the FE on port 9030, patch-pinned like _DORIS_IMAGE: the
# bare 8.0 tag floats (Docker Hub's 8/8.x now track the 8.4 series).
_MYSQL_CLIENT_IMAGE = "mysql:8.0.46"
DORIS_CONTAINER = "mcp-auditor-cve-doris"
DORIS_BRIDGE = "mcp-auditor-cve-doris-bridge"  # server <-> Doris FE, name resolution
_DORIS_LLNET = "mcp-auditor-cve-doris-llnet"  # Doris <-> sentinels, static link-local IPs
_DORIS_LLSUBNET = "169.254.0.0/16"
DORIS_DB = "test_db"  # the database the server validates at connect, read by the exploit/benign
_DORIS_HEALTH_DEADLINE = 240.0
_DORIS_BACKEND_DEADLINE = 180.0

# The sentinel is a singleton: it sits at the fixed metadata IP the exploit payload fetches, so it
# cannot be made per-launch-unique. This serializes the target's concurrent scored runs instead,
# held across the yield so a run's teardown cannot reap the next run's live sentinel. A plain Lock,
# not an RLock: `entered_in_thread` runs __enter__ and __exit__ as separate `asyncio.to_thread`
# submissions, so the acquiring and releasing worker threads may differ, which a plain Lock allows
# and an owner-bound RLock would reject with RuntimeError out of __exit__.
DORIS_LAUNCH_LOCK = threading.Lock()


def ensure_doris() -> None:
    _doris_network(DORIS_BRIDGE)
    _doris_network(_DORIS_LLNET, _DORIS_LLSUBNET)
    if not _doris_running():
        if _doris_exists():
            doris_rm(DORIS_CONTAINER)
        _doris_run(
            "docker", "run", "-d",
            "--name", DORIS_CONTAINER,
            "--hostname", DORIS_CONTAINER,
            "--label", LABEL,
            "--network", DORIS_BRIDGE,
            _DORIS_IMAGE,
        )  # fmt: skip
    _doris_run("docker", "network", "connect", _DORIS_LLNET, DORIS_CONTAINER, check=False)
    _wait_doris_healthy()
    _provision_doris_schema()


def _wait_doris_healthy() -> None:
    deadline = time.monotonic() + _DORIS_HEALTH_DEADLINE
    while time.monotonic() < deadline:
        status = _doris_run(
            "docker", "inspect", "-f", "{{.State.Health.Status}}", DORIS_CONTAINER, check=False
        )
        if status.stdout.strip() == "healthy":
            return
        time.sleep(5)
    raise RuntimeError("Doris front-end did not become healthy")


def _provision_doris_schema() -> None:
    # A bucketed table and a read of it both need a live backend, so retrying until both succeed
    # gates the yield on backend readiness: the exploit's fetch runs on the backend, and a backend
    # not yet up would otherwise read as a dead condition rather than a slow start.
    deadline = time.monotonic() + _DORIS_BACKEND_DEADLINE
    while time.monotonic() < deadline:
        _doris_sql(f"CREATE DATABASE IF NOT EXISTS {DORIS_DB};")
        created = _doris_sql(
            f"CREATE TABLE IF NOT EXISTS {DORIS_DB}.t1 (id INT) "
            "DISTRIBUTED BY HASH(id) BUCKETS 1 PROPERTIES('replication_num'='1');"
        )
        readable = _doris_sql(f"SELECT COUNT(*) FROM {DORIS_DB}.t1;")
        if created.returncode == 0 and readable.returncode == 0:
            return
        time.sleep(3)
    raise RuntimeError("Doris backend did not become query-ready")


def start_doris_sentinel(sentinel: SentinelIntent) -> str:
    # A uuid name under the launch lock: nothing from a sibling run can collide with or be
    # force-removed by this one. The static --ip stays, it is the metadata IP the exploit targets.
    name = f"{LABEL}-doris-sentinel-{uuid4().hex}"
    _doris_run(
        "docker", "run", "-d",
        "--name", name,
        "--label", LABEL,
        *confinement_args(),
        "--network", _DORIS_LLNET,
        "--ip", sentinel.host,
        "--cap-add", "NET_BIND_SERVICE",
        "-e", f"FLAG={sentinel.content}",
        "-e", f"SERVE_FILE={sentinel.served_file}",
        SENTINEL_IMAGE,
    )  # fmt: skip
    return name


def _doris_running() -> bool:
    return DORIS_CONTAINER in _doris_names("docker", "ps")


def _doris_exists() -> bool:
    return DORIS_CONTAINER in _doris_names("docker", "ps", "-a")


def _doris_names(*ps_command: str) -> list[str]:
    result = _doris_run(
        *ps_command, "--filter", f"name=^{DORIS_CONTAINER}$", "--format", "{{.Names}}", check=False
    )
    return result.stdout.split()


def _doris_network(name: str, subnet: str | None = None) -> None:
    listed = _doris_run("docker", "network", "ls", "--format", "{{.Name}}", check=False)
    if name in listed.stdout.split():
        return
    args = ["docker", "network", "create", "--label", LABEL, name]
    if subnet is not None:
        args += ["--subnet", subnet]
    _doris_run(*args)


def _doris_sql(sql: str) -> subprocess.CompletedProcess[str]:
    return _doris_run(
        "docker", "run", "--rm", "--label", LABEL, "--network", DORIS_BRIDGE, _MYSQL_CLIENT_IMAGE,
        "mysql", f"-h{DORIS_CONTAINER}", "-P9030", "-uroot", "--batch", "-e", sql,
        check=False, timeout=60,
    )  # fmt: skip


def _doris_run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


def doris_rm(name: str) -> None:
    with suppress(subprocess.SubprocessError, OSError):
        _doris_run("docker", "rm", "-f", name, check=False)
