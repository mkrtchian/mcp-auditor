"""apache/gravitino's MCP server fix-check fixture: CVE-2026-41041 (path injection through a
caller-supplied identifier).

The MCP server builds each Gravitino REST path by interpolating identifiers into an f-string
without percent-encoding, so dot-segments in a caller-supplied identifier are resolved by httpx
(RFC 3986 remove_dot_segments against the metalake-scoped base URL) and the request leaves the
metalake the server is launched for. `get_list_of_schemas` with `../../hidden/catalogs/secretcat`
reaches a sibling metalake's catalog and lists its schemas: reach = internal_fetch. The patched
client wraps every path identifier in `urllib.parse.quote(segment, safe="")`, so the dot-segments
are encoded and the request stays inside `analytics`. Every counted tool carries the same
unencoded interpolation, so each has an exploit that injects the traversal into its own identifier;
only `get_list_of_schemas` lists schema names, so the planted nonce surfaces through it.

The run singleton never carries the witness (it is where every nuisance run reads), so the builder
stands its own Gravitino stack (the backend's three parts) on a per-launch closed network, seeds
the benign `analytics` metalake plus a sibling `hidden` metalake whose `secretcat` catalog holds one
schema named the planted nonce, points the server's `--gravitino-uri` at that stack's `gravitino`,
and reaps the containers and the network. The benign calls read `analytics`, so the stack keeps the
Postgres and the Kafka the relational and messaging catalogs manage.
"""

import json
import re
import secrets
import subprocess
import time
from collections.abc import Awaitable, Callable, Generator, Sequence
from contextlib import contextmanager
from typing import Any

from evals.cve.backends.gravitino import (
    EVENTS_DIRECTORY,
    GRAVITINO_PARTS,
    GRAVITINO_PORT,
    GRAVITINO_SEED,
    METALAKE,
)
from evals.cve.closed_network import create_closed_network
from evals.cve.docker_paths import DOCKER_DIRECTORY, image_dockerfile
from evals.cve.grammar import FlawClass
from evals.cve.kit.client import KitClient
from evals.cve.kit.fix_check import FixCheckFixture
from evals.cve.kit.launch import Launch, LaunchShape
from evals.cve.places import Coordinates, Place, PlaceKind, Places
from evals.cve.planting import (
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    confinement_args,
    unprivileged_user_args,
)
from evals.cve.planting_base import LABEL, own_network_args

HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/tmp", has_network=True)

WITNESS = Place(
    id="gravitino-41041-hidden-schema",
    family="fix_check",
    reaches=frozenset({"internal_fetch"}),
    # The nonce is a token seeded as a schema name under the sibling metalake, not an address: the
    # surfacing is the nonce appearing in the traversal's response, graded by the aim and the nonce.
    kind=PlaceKind.HOSTNAME,
    coordinates=Coordinates(PlaceKind.HOSTNAME),
)

_HIDDEN_METALAKE = "hidden"
_HIDDEN_CATALOG = "secretcat"
_TRAVERSAL = f"../../{_HIDDEN_METALAKE}/catalogs/{_HIDDEN_CATALOG}"
# An exploit is aimed when an identifier carries the dot-segment traversal into the sibling
# metalake. The benign calls carry seeded names only, so none is aimed.
AIM = re.compile(re.escape(_TRAVERSAL))
_INSTANCE_ALIAS = "gravitino"
_SERVER_URI = f"http://{_INSTANCE_ALIAS}:{GRAVITINO_PORT}"
_SERVER_LAUNCH = ["--metalake", METALAKE, "--gravitino-uri", _SERVER_URI]
_API = f"http://localhost:{GRAVITINO_PORT}/api"
_READY_SECONDS = 300.0

# (tool, benign arguments, the identifier the traversal is injected into) for each counted tool.
_TOOLS: tuple[tuple[str, dict[str, Any], str], ...] = (
    ("get_list_of_schemas", {"catalog_name": "lakehouse"}, "catalog_name"),
    ("get_list_of_tables", {"catalog_name": "warehouse", "schema_name": "retail"}, "catalog_name"),
    (
        "get_table_metadata_details",
        {"catalog_name": "warehouse", "schema_name": "retail", "table_name": "orders"},
        "catalog_name",
    ),
    ("list_of_topics", {"catalog_name": "streams", "schema_name": "default"}, "catalog_name"),
    (
        "load_topic",
        {"catalog_name": "streams", "schema_name": "default", "topic_name": "clicks"},
        "catalog_name",
    ),
    ("list_of_models", {"catalog_name": "registry", "schema_name": "prod"}, "catalog_name"),
    (
        "load_model",
        {"catalog_name": "registry", "schema_name": "prod", "model_name": "ranker"},
        "catalog_name",
    ),
    (
        "list_model_versions",
        {"catalog_name": "registry", "schema_name": "prod", "model_name": "ranker"},
        "catalog_name",
    ),
    (
        "load_model_version",
        {"catalog_name": "registry", "schema_name": "prod", "model_name": "ranker", "version": 0},
        "catalog_name",
    ),
    (
        "load_model_version_by_alias",
        {
            "catalog_name": "registry",
            "schema_name": "prod",
            "model_name": "ranker",
            "alias": "stable",
        },
        "catalog_name",
    ),
    ("list_of_filesets", {"catalog_name": "lakehouse", "schema_name": "sales"}, "catalog_name"),
    (
        "load_fileset",
        {"catalog_name": "lakehouse", "schema_name": "sales", "fileset_name": "events"},
        "catalog_name",
    ),
    (
        "list_files_in_fileset",
        {
            "catalog_name": "lakehouse",
            "schema_name": "sales",
            "fileset_name": "events",
            "location_name": "unknown",
        },
        "catalog_name",
    ),
    ("get_tag_by_name", {"tag_name": "gold"}, "tag_name"),
    ("list_metadata_by_tag", {"tag_name": "gold"}, "tag_name"),
    (
        "list_tags_for_metadata",
        {"metadata_full_name": "lakehouse", "metadata_type": "catalog"},
        "metadata_full_name",
    ),
    (
        "associate_tag_with_metadata",
        {
            "metadata_full_name": "lakehouse.sales",
            "metadata_type": "schema",
            "tags_to_associate": ["gold"],
        },
        "metadata_full_name",
    ),
    (
        "disassociate_tag_from_metadata",
        {
            "metadata_full_name": "lakehouse.sales",
            "metadata_type": "schema",
            "tags_to_disassociate": ["gold"],
        },
        "metadata_full_name",
    ),
    ("get_policy_detail_information", {"policy_name": "retention"}, "policy_name"),
    ("list_metadata_by_policy", {"policy_name": "retention"}, "policy_name"),
    (
        "list_policies_for_metadata",
        {"metadata_full_name": "lakehouse", "metadata_type": "catalog"},
        "metadata_full_name",
    ),
    (
        "get_policy_for_metadata",
        {"metadata_full_name": "lakehouse", "metadata_type": "catalog", "policy_name": "retention"},
        "metadata_full_name",
    ),
    (
        "associate_policy_with_metadata",
        {
            "metadata_full_name": "lakehouse.sales",
            "metadata_type": "schema",
            "policies_to_add": ["retention"],
        },
        "metadata_full_name",
    ),
    (
        "disassociate_policy_from_metadata",
        {
            "metadata_full_name": "lakehouse.sales",
            "metadata_type": "schema",
            "policies_to_remove": ["retention"],
        },
        "metadata_full_name",
    ),
    (
        "list_statistics_for_metadata",
        {
            "metalake_name": "analytics",
            "metadata_type": "table",
            "metadata_fullname": "warehouse.retail.orders",
        },
        "metadata_fullname",
    ),
    (
        "list_statistics_for_partition",
        {
            "metalake_name": "analytics",
            "metadata_type": "table",
            "metadata_fullname": "warehouse.retail.orders",
            "from_partition_name": "a",
            "to_partition_name": "z",
        },
        "metadata_fullname",
    ),
    ("get_job_template_by_name", {"name": "builtin-iceberg-rewrite-data-files"}, "name"),
)

_PROBES: dict[str, list[str]] = {
    "gravitino": ["curl", "-fsS", "-o", "/dev/null", f"{_API}/version"],
    "postgres": ["pg_isready", "-h", "127.0.0.1", "-U", "grav", "-d", "warehouse"],
    "kafka": ["/opt/kafka/bin/kafka-topics.sh", "--bootstrap-server", "localhost:9092", "--list"],
}


def part_args(name: str, network: str, alias: str, image: str) -> list[str]:
    return [
        "run", "-d", "--rm",
        "--name", name,
        "--label", LABEL,
        *own_network_args(network),
        "--network-alias", alias,
        *confinement_args(),
        image,
    ]  # fmt: skip


def server_args(image: str, network: str) -> list[str]:
    return [
        "run", "-i", "--rm",
        *confinement_args(),
        *own_network_args(network),
        *unprivileged_user_args(),
        "-w", HOST.working_directory,
        image,
        *_SERVER_LAUNCH,
    ]  # fmt: skip


@contextmanager
def gravitino_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    _ensure_part_images()
    network = f"mcp-auditor-kit-gravitino-net-{secrets.token_hex(6)}"
    create_closed_network(network)
    containers: list[tuple[str, str]] = []  # (alias, container name)
    try:
        for part in GRAVITINO_PARTS:
            name = f"mcp-auditor-kit-gravitino-{part.alias}-{secrets.token_hex(4)}"
            subprocess.run(
                ["docker", *part_args(name, network, part.alias, part.image)],
                check=True, capture_output=True,
            )  # fmt: skip
            containers.append((part.alias, name))
        _wait_ready(containers)
        _seed(_container(containers, _INSTANCE_ALIAS), spec.nonces[WITNESS.id])
        yield Launch(command="docker", args=server_args(image, network))
    finally:
        for _, name in containers:
            _rm(name)
        subprocess.run(["docker", "network", "rm", network], capture_output=True)


def _ensure_part_images() -> None:
    for part in GRAVITINO_PARTS:
        if (
            subprocess.run(
                ["docker", "image", "inspect", part.image], capture_output=True
            ).returncode
            != 0
        ):
            subprocess.run(
                ["docker", "build", "-t", part.image,
                 "-f", str(image_dockerfile(part.service)), str(DOCKER_DIRECTORY)],
                check=True, timeout=1800.0,
            )  # fmt: skip


def _wait_ready(containers: Sequence[tuple[str, str]]) -> None:
    for alias, name in containers:
        _wait_until(name, _PROBES[alias])


def _wait_until(container: str, probe: Sequence[str]) -> None:
    deadline = time.monotonic() + _READY_SECONDS
    while (
        subprocess.run(["docker", "exec", container, *probe], capture_output=True).returncode != 0
    ):
        if time.monotonic() > deadline:
            raise RuntimeError(f"{container} did not answer within {_READY_SECONDS:.0f}s")
        time.sleep(3)


def _seed(instance: str, nonce: str) -> None:
    for request in GRAVITINO_SEED:
        _request(instance, request.method, f"/metalakes{request.path}", request.body)
    _exec(instance, "mkdir", "-p", EVENTS_DIRECTORY)
    _exec(instance, "sh", "-c", f"printf hi > {EVENTS_DIRECTORY}/part-000.txt")
    _request(
        instance,
        "POST",
        "/metalakes",
        {"name": _HIDDEN_METALAKE, "comment": "demo", "properties": {}},
    )
    _request(
        instance,
        "POST",
        f"/metalakes/{_HIDDEN_METALAKE}/catalogs",
        {
            "name": _HIDDEN_CATALOG,
            "type": "fileset",
            "provider": "hadoop",
            "comment": "demo",
            "properties": {"location": "file:/tmp/secret"},
        },
    )
    _request(
        instance,
        "POST",
        f"/metalakes/{_HIDDEN_METALAKE}/catalogs/{_HIDDEN_CATALOG}/schemas",
        {"name": nonce, "comment": "demo", "properties": {}},
    )


def _request(instance: str, method: str, path: str, body: dict[str, Any]) -> None:
    _exec(
        instance,
        "curl", "-fsS", "-X", method, "-H", "Content-Type: application/json",
        "-d", json.dumps(body), f"{_API}{path}",
    )  # fmt: skip


def _exec(container: str, *command: str) -> None:
    subprocess.run(
        ["docker", "exec", container, *command], check=True, capture_output=True, timeout=180.0
    )


def _container(containers: Sequence[tuple[str, str]], alias: str) -> str:
    return next(name for part_alias, name in containers if part_alias == alias)


def _rm(name: str) -> None:
    subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True)


FixCheckExploit = Callable[[Places, KitClient], Awaitable[None]]


def _call(tool: str, arguments: dict[str, Any]) -> FixCheckExploit:
    async def call(places: Places, client: KitClient) -> None:
        await client.call_tool(tool, arguments)

    return call


EXPLOITS = tuple(_call(tool, {**benign, field: _TRAVERSAL}) for tool, benign, field in _TOOLS)
BENIGN_CALLS = tuple(_call(tool, benign) for tool, benign, _ in _TOOLS)


FIXTURE = FixCheckFixture(
    flaw="CVE-2026-41041",
    effect_class=FlawClass.INTERNAL_FETCH,
    aim=AIM,
    witness=WITNESS,
    planting_host=HOST,
    builder=gravitino_env,
    exploits=EXPLOITS,
    benign_calls=BENIGN_CALLS,
    vulnerable_service="gravitino-vuln",
    patched_service="gravitino",
    server_patched_service=None,  # the server's patched version is the flaw's: 1.2.1
)

FIXTURES = (FIXTURE,)
