"""The Gravitino backend's lifecycle: the real Apache Gravitino server the MCP server calls, with
the PostgreSQL and the Kafka its relational and messaging catalogs manage.

Gravitino's MCP server is a thin client of Gravitino's REST API (`--gravitino-uri`), scoped to one
metalake (`--metalake`). Gravitino 1.2.1 runs here by its digest, PostgreSQL 16 under its
jdbc-postgresql catalog and Kafka 4.4.0 under its kafka catalog, each a built part whose Dockerfile
pins its image, each in its own container under the nuisance confinement with no added capability,
on one closed labeled bridge (no route to the host or the Internet) at a fixed address. The
server reaches Gravitino under the alias `gravitino`, and Gravitino reaches the other two under
`postgres` and `kafka`.

At each stand-up `ensure_gravitino_backend` checks that Gravitino answers 1.2.1, then replays the
seed through Gravitino's REST API with `docker exec` inside the instance (the host cannot reach a
closed bridge) when the metalake is absent: the metalake, a fileset, a model, a jdbc-postgresql
and a kafka catalog with their objects, a tag and a policy on the `lakehouse` catalog and a second
of each on its `sales` schema, every value written for the fixture.
The backend's state lives in its containers only, so a stand-up after their removal starts from
the images and the seed. The backend carries no witness: a fix check stands its own instance.

The stack is a singleton, stood once and reused across a server's concurrent nuisance runs,
reaped by the generic orphan sweep, so no lock is held across the yield.
"""

import json
import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from evals.backend_lifecycle import BackendLifecycle
from evals.closed_network import ensure_closed_network
from evals.cve_planting_base import LABEL, PlantingHost, own_network_args
from evals.docker_paths import DOCKER_DIRECTORY, image_dockerfile
from evals.nuisance_confinement import (
    labelled_run_args,
    nuisance_confinement_args,
    running_with_launch,
    user_args,
)
from evals.responder_backend import remove

GRAVITINO_BRIDGE = "mcp-auditor-cve-gravitino-bridge"
GRAVITINO_SUBNET = "198.18.7.0/24"  # RFC 2544: overlaps no other backend's subnet
GRAVITINO_RELEASE = "1.2.1"
METALAKE = "analytics"
GRAVITINO_PORT = 8090
GRAVITINO_SERVER_LAUNCH = [
    "--metalake", METALAKE, "--gravitino-uri", f"http://gravitino:{GRAVITINO_PORT}",
]  # fmt: skip
_API = f"http://localhost:{GRAVITINO_PORT}/api"
_READY_SECONDS = 300.0

# The stack is a singleton, so a caller does not hold this across its yield: a server's concurrent
# runs share it. A plain Lock serialises only the stand-up, since __enter__ and __exit__ may run on
# different worker threads.
GRAVITINO_LAUNCH_LOCK = threading.Lock()


@dataclass(frozen=True)
class GravitinoPart:
    container: str
    service: str  # the compose service building its image
    ip: str
    alias: str  # the name the server and the other parts reach it by

    @property
    def image(self) -> str:
        return f"mcp-auditor-cve-{self.service}:local"

    def run_args(self) -> list[str]:
        return [
            "run", "-d",
            "--name", self.container,
            "--label", LABEL,
            *own_network_args(GRAVITINO_BRIDGE),
            "--ip", self.ip,
            "--network-alias", self.alias,
            *nuisance_confinement_args(),
            self.image,
        ]  # fmt: skip


_INSTANCE = GravitinoPart(
    "mcp-auditor-cve-gravitino-instance", "gravitino-instance", "198.18.7.2", "gravitino"
)
_DB = GravitinoPart("mcp-auditor-cve-gravitino-db", "gravitino-db", "198.18.7.3", "postgres")
_KAFKA = GravitinoPart("mcp-auditor-cve-gravitino-kafka", "gravitino-kafka", "198.18.7.4", "kafka")
GRAVITINO_PARTS = (_INSTANCE, _DB, _KAFKA)
GRAVITINO_IMAGE = _INSTANCE.image
GRAVITINO_SERVICES = tuple(part.service for part in GRAVITINO_PARTS)


@dataclass(frozen=True)
class SeedRequest:
    method: str
    path: str  # under the metalakes endpoint
    body: dict[str, Any]


def _catalog(name: str, kind: str, provider: str, **properties: str) -> SeedRequest:
    body: dict[str, Any] = {"name": name, "type": kind, "provider": provider, "comment": "demo"}
    return SeedRequest("POST", f"/{METALAKE}/catalogs", body | {"properties": properties})


def _named(path: str, name: str, **fields: Any) -> SeedRequest:
    no_properties: dict[str, str] = {}
    body: dict[str, Any] = {"name": name, "comment": "demo", "properties": no_properties}
    return SeedRequest("POST", f"/{METALAKE}{path}", body | fields)


_WAREHOUSE = {
    "jdbc-url": "jdbc:postgresql://postgres:5432/warehouse",
    "jdbc-user": "grav",
    "jdbc-password": "grav",
    "jdbc-database": "warehouse",
    "jdbc-driver": "org.postgresql.Driver",
}
_ORDERS_COLUMNS = [
    {"name": "id", "type": "integer", "comment": "c", "nullable": False},
    {"name": "amount", "type": "integer", "comment": "c", "nullable": True},
]
_RETENTION = {
    "policyType": "custom",
    "enabled": True,
    "content": {
        "customRules": {"k": "v"},
        "supportedObjectTypes": ["CATALOG", "SCHEMA", "FILESET"],
    },
}
EVENTS_DIRECTORY = "/tmp/lakehouse/events"

GRAVITINO_SEED: tuple[SeedRequest, ...] = (
    SeedRequest("POST", "", {"name": METALAKE, "comment": "demo", "properties": {}}),
    _catalog("lakehouse", "fileset", "hadoop", location="file:/tmp/lakehouse"),
    _named("/catalogs/lakehouse/schemas", "sales"),
    _named(
        "/catalogs/lakehouse/schemas/sales/filesets",
        "events",
        type="managed",
        storageLocation=f"file:{EVENTS_DIRECTORY}",
    ),
    _catalog("registry", "model", "model"),
    _named("/catalogs/registry/schemas", "prod"),
    _named("/catalogs/registry/schemas/prod/models", "ranker"),
    SeedRequest(
        "POST",
        f"/{METALAKE}/catalogs/registry/schemas/prod/models/ranker/versions",
        {"uri": "file:/tmp/ranker/v0", "aliases": ["stable"], "comment": "demo", "properties": {}},
    ),
    _catalog("warehouse", "relational", "jdbc-postgresql", **_WAREHOUSE),
    _named("/catalogs/warehouse/schemas", "retail"),
    _named("/catalogs/warehouse/schemas/retail/tables", "orders", columns=_ORDERS_COLUMNS),
    SeedRequest(
        "PUT",
        f"/{METALAKE}/objects/table/warehouse.retail.orders/statistics",
        {"updates": {"custom-row-count": 100}},
    ),
    _catalog("streams", "messaging", "kafka", **{"bootstrap.servers": "kafka:9092"}),
    _named(
        "/catalogs/streams/schemas/default/topics",
        "clicks",
        properties={"partition-count": "1", "replication-factor": "1"},
    ),
    _named("/tags", "gold"),
    _named("/tags", "silver"),
    SeedRequest(
        "POST", f"/{METALAKE}/policies", {"name": "retention", "comment": "demo"} | _RETENTION
    ),
    SeedRequest(
        "POST", f"/{METALAKE}/policies", {"name": "compaction", "comment": "demo"} | _RETENTION
    ),
    SeedRequest(
        "POST",
        f"/{METALAKE}/objects/catalog/lakehouse/tags",
        {"tagsToAdd": ["gold"], "tagsToRemove": []},
    ),
    SeedRequest(
        "POST",
        f"/{METALAKE}/objects/catalog/lakehouse/policies",
        {"policiesToAdd": ["retention"], "policiesToRemove": []},
    ),
    # silver and compaction sit on the sales schema, so the associate benign calls (which add gold
    # and retention there) return a name they did not pass in, which the expect keys on.
    SeedRequest(
        "POST",
        f"/{METALAKE}/objects/schema/lakehouse.sales/tags",
        {"tagsToAdd": ["silver"], "tagsToRemove": []},
    ),
    SeedRequest(
        "POST",
        f"/{METALAKE}/objects/schema/lakehouse.sales/policies",
        {"policiesToAdd": ["compaction"], "policiesToRemove": []},
    ),
)


def gravitino_server_args(
    name: str, image: str, host: PlantingHost, server_launch: Sequence[str]
) -> list[str]:
    return [
        "run", "-i", "--rm",
        *nuisance_confinement_args(),
        "--name", name,
        "--label", LABEL,
        *own_network_args(GRAVITINO_BRIDGE),
        *user_args(host.user),
        "-w", host.working_directory,
        image,
        *server_launch,
    ]  # fmt: skip


def ensure_gravitino_backend() -> None:
    for part in GRAVITINO_PARTS:
        _ensure_image(part)
    ensure_closed_network(GRAVITINO_BRIDGE, "--subnet", GRAVITINO_SUBNET)
    _ensure_running()
    _wait_until(_DB, "pg_isready", "-h", "127.0.0.1", "-U", "grav", "-d", "warehouse")
    _wait_until(
        _KAFKA, "/opt/kafka/bin/kafka-topics.sh", "--bootstrap-server", "localhost:9092", "--list"
    )
    _wait_until(_INSTANCE, "curl", "-fsS", "-o", "/dev/null", f"{_API}/version")
    _check_the_release()
    if not _seeded():
        _seed()


def _ensure_image(part: GravitinoPart) -> None:
    if _run("docker", "image", "inspect", part.image, check=False).returncode != 0:
        dockerfile = image_dockerfile(part.service)
        _run(
            "docker", "build", "-t", part.image, "-f", str(dockerfile), str(DOCKER_DIRECTORY),
            timeout=1800.0,
        )  # fmt: skip


def _ensure_running() -> None:
    # The seed spans the three parts (Gravitino's catalogs over PostgreSQL's schema and Kafka's
    # topic), so one part started again restarts them all and the seed is replayed whole.
    if all(running_with_launch(part.container, part.run_args()) for part in GRAVITINO_PARTS):
        return
    _remove_the_parts()
    for part in GRAVITINO_PARTS:
        _run("docker", *labelled_run_args(part.run_args()))


def _remove_the_parts() -> None:
    for part in GRAVITINO_PARTS:
        remove(part.container)


def _wait_until(part: GravitinoPart, *probe: str) -> None:
    deadline = time.monotonic() + _READY_SECONDS
    while _run("docker", "exec", part.container, *probe, check=False).returncode != 0:
        if time.monotonic() > deadline:
            raise RuntimeError(f"{part.container} did not answer within {_READY_SECONDS:.0f}s")
        time.sleep(3)


def _check_the_release() -> None:
    answer = json.loads(_in_the_instance("curl", "-fsS", f"{_API}/version"))
    release = answer["version"]["version"]
    if release != GRAVITINO_RELEASE:
        raise RuntimeError(f"Gravitino answers {release}, not {GRAVITINO_RELEASE}")


def _seeded() -> bool:
    status = _in_the_instance(
        "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", f"{_API}/metalakes/{METALAKE}"
    )
    return status == "200"


def _seed() -> None:
    # The metalake is the first request, so a seed that fails part way would read as done: the
    # parts go, and the next stand-up starts them again from their images.
    try:
        _replay_the_seed()
    except subprocess.SubprocessError:
        _remove_the_parts()
        raise


def _replay_the_seed() -> None:
    for request in GRAVITINO_SEED:
        _in_the_instance(
            "curl", "-fsS", "-X", request.method,
            "-H", "Content-Type: application/json",
            "-d", json.dumps(request.body),
            f"{_API}/metalakes{request.path}",
        )  # fmt: skip
    _in_the_instance("mkdir", "-p", EVENTS_DIRECTORY)
    _in_the_instance("sh", "-c", f"printf hi > {EVENTS_DIRECTORY}/part-000.txt")


def _in_the_instance(*command: str) -> str:
    return _run("docker", "exec", _INSTANCE.container, *command, timeout=180.0).stdout.strip()


def gravitino_rm(name: str) -> None:
    remove(name)


def _run(
    *args: str, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=timeout)


LIFECYCLE = BackendLifecycle(
    "gravitino",
    GRAVITINO_LAUNCH_LOCK,
    ensure_gravitino_backend,
    gravitino_server_args,
    gravitino_rm,
)
