"""The Doris cluster backend's lifecycle.

A persistent Doris FE+BE cluster: a JVM front-end and back-end, heavy and slow to stand up, so it
is provisioned once and reused across every exercise rather than per launch; only the per-launch
sentinels are stood and torn down per run. This module owns that lifecycle, kept apart from the
launch-construction concern of `holdout_environments`: ensuring the cluster is up and query-ready
(the front-end health wait, then the seeding of Doris' quick-start sample, which gates on a live
back-end), standing a sentinel on the static-IP link-local network the back-end reaches, and the
thin `docker` wrappers underneath. Both networks are closed: no route to the host or the Internet.

A caller drives this through `ensure_doris`, `start_doris_sentinel`, `doris_rm` and
`DORIS_LAUNCH_LOCK`, wiring `DORIS_HOST` and `DORIS_BRIDGE` into the server launch: the server
reaches the cluster by its alias `DORIS_HOST`, while the host-side tools address it by
`DORIS_CONTAINER`. `DORIS_DB` names the seeded sample database the fixtures query, not a launch
argument. `doris_server_args` assembles that launch's `docker run` arguments.

The persistent cluster and its two networks are left running on purpose (reused across
exercises); the generic orphan sweep documented in `cve_environments` reaps anything labelled
`mcp-auditor-cve`, the sentinels included.
"""

import secrets
import subprocess
import threading
import time
from collections.abc import Sequence
from contextlib import suppress
from uuid import uuid4

from evals.backend_lifecycle import BackendLifecycle
from evals.closed_network import ensure_closed_network
from evals.cve_planting import confinement_args
from evals.cve_planting_base import (
    LABEL,
    SENTINEL_IMAGE,
    PlantingHost,
    SentinelIntent,
    own_network_args,
)
from evals.nuisance_confinement import (
    labelled_run_args,
    memory_bound_args,
    nuisance_confinement_args,
    running_with_launch,
    user_args,
)

DORIS_IMAGE = (
    "apache/doris:all-in-one-4.1.3"
    "@sha256:82a5cabc7900ebcd3d080412d636c0cebd6602799fffe2605c652b2ea7d42609"
)
# a throwaway MySQL-protocol client for the FE on port 9030, pinned by digest like DORIS_IMAGE:
# the bare 8.0 tag floats across its patch releases, and a tag can be rewritten.
MYSQL_CLIENT_IMAGE = (
    "mysql:8.0.46@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b"
)
DORIS_CONTAINER = "mcp-auditor-cve-doris"
DORIS_HOST = "doris"  # the cluster's hostname and alias on DORIS_BRIDGE
DORIS_BRIDGE = "mcp-auditor-cve-doris-bridge"  # server <-> Doris FE, name resolution
_DORIS_LLNET = "mcp-auditor-cve-doris-llnet"  # Doris <-> sentinels, static link-local IPs
_DORIS_LLSUBNET = "169.254.0.0/16"
DORIS_DB = "demo"  # the database of Doris' quick-start sample, the one the fixture seeds
_DORIS_HEALTH_DEADLINE = 240.0
_DORIS_BACKEND_DEADLINE = 180.0

# The quick-start sample of the Doris 4.x documentation, taken whole: "Create a database and table"
# and "Load test data" of versioned_docs/version-4.x/getting-started/quick-start.mdx at
# apache/doris-website commit 060685ca7597183b740b337fbef4fb1ec81f2683. `IF NOT EXISTS` and the
# empty-table guard on the insert are the only additions, the cluster persisting across launches.
_SAMPLE_SCHEMA = """create database if not exists demo;
use demo;

create table if not exists mytable
(
    k1 TINYINT,
    k2 DECIMAL(10, 2) DEFAULT "10.05",
    k3 CHAR(10) COMMENT "string column",
    k4 INT NOT NULL DEFAULT "1" COMMENT "int column"
)
COMMENT "my first table"
DISTRIBUTED BY HASH(k1) BUCKETS 1
PROPERTIES ("replication_num" = "1");"""
_SAMPLE_ROWS = """insert into demo.mytable values
(1, 0.14, 'a1', 20),
(2, 1.04, 'b2', 21),
(3, 3.14, 'c3', 22),
(4, 4.35, 'd4', 23);"""

# The server's documented defaults hold for the port (9030), the user (root, no password) and the
# database (information_schema): only the host the cluster answers on is set.
DORIS_SERVER_LAUNCH: list[str] = ["--db-host", DORIS_HOST]

# The sentinel is a singleton on a fixed link-local IP, so it cannot be made per-launch-unique. A
# caller that stands one holds this across its yield to serialise the concurrent runs that share
# that one sentinel, so a run's teardown cannot reap the next run's live sentinel. A plain Lock,
# not an RLock: `entered_in_thread` runs __enter__ and __exit__ as separate `asyncio.to_thread`
# submissions, so the acquiring and releasing worker threads may differ, which a plain Lock allows
# and an owner-bound RLock would reject with RuntimeError out of __exit__.
DORIS_LAUNCH_LOCK = threading.Lock()


def doris_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return [
        "run", "-i", "--rm",
        *nuisance_confinement_args(),
        "--name", name,
        "--label", LABEL,
        *own_network_args(DORIS_BRIDGE),
        *user_args(host.user),
        "-w", host.working_directory,
        image,
        *server_launch,
    ]  # fmt: skip


def ensure_doris() -> None:
    ensure_closed_network(DORIS_BRIDGE)
    ensure_closed_network(_DORIS_LLNET, "--subnet", _DORIS_LLSUBNET)
    if not running_with_launch(DORIS_CONTAINER, doris_cluster_run_args()):
        if _doris_exists():
            doris_rm(DORIS_CONTAINER)
        _doris_run("docker", *labelled_run_args(doris_cluster_run_args()))
    _doris_run("docker", "network", "connect", _DORIS_LLNET, DORIS_CONTAINER, check=False)
    _wait_doris_healthy()
    _provision_doris_schema()


def doris_cluster_run_args() -> list[str]:
    return [
        "run", "-d",
        "--name", DORIS_CONTAINER,
        "--hostname", DORIS_HOST,
        "--label", LABEL,
        *own_network_args(DORIS_BRIDGE),
        "--network-alias", DORIS_HOST,
        *memory_bound_args(),
        # The all-in-one image registers its BE on loopback, so the Arrow Flight SQL endpoint the FE
        # hands an ADBC client is 127.0.0.1, which a client in another container cannot reach. The
        # Doris documentation's remedy (Arrow Flight SQL, FAQ "Error i/o timeout", case 2) is the
        # BE's `public_host` set to an address the client reaches; the image appends
        # BE_CONFIG_EXTRA to be.conf (/opt/doris-ci/entrypoint.sh).
        "-e", f"BE_CONFIG_EXTRA=public_host = {DORIS_HOST}",
        DORIS_IMAGE,
    ]  # fmt: skip


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
    # A bucketed table, an insert and a read all need a live back-end, so retrying until they
    # succeed gates the yield on back-end readiness: a back-end not yet up would otherwise look like
    # a permanent failure rather than a slow start.
    deadline = time.monotonic() + _DORIS_BACKEND_DEADLINE
    while time.monotonic() < deadline:
        created = _doris_sql(_SAMPLE_SCHEMA)
        counted = _doris_sql("SELECT COUNT(*) FROM demo.mytable;")
        if created.returncode == 0 and counted.returncode == 0:
            if counted.stdout.split()[-1:] == ["4"]:
                return
            if counted.stdout.split()[-1:] == ["0"]:
                _doris_sql(_SAMPLE_ROWS)
        time.sleep(3)
    raise RuntimeError("Doris backend did not become query-ready")


def start_doris_sentinel(sentinel: SentinelIntent) -> str:
    # A uuid name under the launch lock: nothing from a sibling run can collide with or be
    # force-removed by this one. The static --ip binds the fixed link-local address configured on
    # the sentinel.
    name = f"{LABEL}-doris-sentinel-{uuid4().hex}"
    _doris_run(
        "docker", "run", "-d",
        "--name", name,
        "--label", LABEL,
        *confinement_args(),
        *own_network_args(_DORIS_LLNET),
        "--ip", sentinel.host,
        "--cap-add", "NET_BIND_SERVICE",
        "-e", f"FLAG={sentinel.content}",
        "-e", f"SERVE_FILE={sentinel.served_file}",
        SENTINEL_IMAGE,
    )  # fmt: skip
    return name


def _doris_exists() -> bool:
    return DORIS_CONTAINER in _doris_names("docker", "ps", "-a")


def _doris_names(*ps_command: str) -> list[str]:
    result = _doris_run(
        *ps_command, "--filter", f"name=^{DORIS_CONTAINER}$", "--format", "{{.Names}}", check=False
    )
    return result.stdout.split()


def _doris_sql(sql: str) -> subprocess.CompletedProcess[str]:
    name = f"{LABEL}-probe-{secrets.token_hex(6)}"
    try:
        return _doris_run(
            "docker", "run", "--rm", "--label", LABEL, "--name", name, "--network", DORIS_BRIDGE,
            MYSQL_CLIENT_IMAGE, "mysql", f"-h{DORIS_CONTAINER}", "-P9030", "-uroot", "--batch",
            "-e", sql, check=False, timeout=60,
        )  # fmt: skip
    finally:
        doris_rm(name)


def _doris_run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


def doris_rm(name: str) -> None:
    with suppress(subprocess.SubprocessError, OSError):
        _doris_run("docker", "rm", "-f", name, check=False)


LIFECYCLE = BackendLifecycle("doris", DORIS_LAUNCH_LOCK, ensure_doris, doris_server_args, doris_rm)
