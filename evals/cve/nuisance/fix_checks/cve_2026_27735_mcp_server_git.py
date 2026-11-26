"""mcp-server-git fix-check fixtures for CVE-2026-27735 and its MinimOS repackaging
MINI-mch8-8h85-3j5v: git_add staged a ../ path resolving outside the repository through GitPython's
index.add, and git_diff_staged then returned its content (read_outside_scope). 2026.1.14 switches to
the git CLI (repo.git.add('--', *files)), which refuses an out-of-tree path.

The flaw lives at the junction of the server and GitPython: GitPython confines index paths to the
work tree from 3.1.58 on (released 2026-08-04), so the vulnerable and patched arms of this fix check
bound gitpython to <3.1.58, the only images that do (Dockerfile.mcp-server-git-vuln and
Dockerfile.mcp-server-git-patched). On the bounded vulnerable 2025.12.18 the traversal stages
/srv/.env and git_diff_staged surfaces it; on the bounded patched 2026.1.14 the server's own fix
rejects the path. The run image floats its dependencies and audits the server's fix on 2026.1.14.

git_diff_staged is listed in the flaw's tools because it is the tool that reveals the staged
content, as context_get is for CVE-2026-54561. Both tools are counted, as under CVE-2025-68145: each
runs a fixed git operation on the repository the launch declares. The benign calls, one per tool,
run on the patched layout checkout without error.
"""

import re

from evals.cve.grammar import FlawClass
from evals.cve.kit.client import KitClient
from evals.cve.kit.fix_check import FixCheckExploit, FixCheckFixture
from evals.cve.kit.launch import git_init_traversal_env
from evals.cve.places import Coordinates, LayoutAnchor, Place, PlaceKind, Places
from evals.cve.planting_base import LayoutMount, PlantingHost, SymbolicUser

_REPO = "/srv/app"  # the declared scope (--repository)
_TRAVERSAL = "../.env"  # /srv/.env, one level above the declared scope

_VULN = "mcp-server-git-vuln"  # 2025.12.18, gitpython<3.1.58
_PATCHED = "mcp-server-git-patched"  # 2026.1.14, gitpython<3.1.58

HOST = PlantingHost(
    user=SymbolicUser.UNPRIVILEGED,
    working_directory="/",
    has_network=False,
    layout_mount=LayoutMount.READ_WRITE,
)


def _fixture(flaw: str, witness_id: str) -> FixCheckFixture:
    return FixCheckFixture(
        flaw=flaw,
        effect_class=FlawClass.READ_OUTSIDE_SCOPE,
        aim=re.compile(r"\.\./"),
        witness=_dotenv_witness(witness_id),
        planting_host=HOST,
        builder=git_init_traversal_env,
        exploits=(_traversal_exploit(),),
        benign_calls=_BENIGN,
        vulnerable_service=_VULN,
        patched_service=_PATCHED,
        server_patched_service=None,
    )


def _dotenv_witness(place_id: str) -> Place:
    return Place(
        id=place_id,
        family="dotenv",
        reaches=frozenset({"arbitrary_read"}),
        kind=PlaceKind.DOTENV,
        coordinates=Coordinates(PlaceKind.DOTENV, anchor=LayoutAnchor.WORKSPACE, relpath=".env"),
    )


def _traversal_exploit() -> FixCheckExploit:
    async def exploit(places: Places, client: KitClient) -> None:
        await client.call_tool("git_add", {"repo_path": _REPO, "files": [_TRAVERSAL]})
        await client.call_tool("git_diff_staged", {"repo_path": _REPO})

    return exploit


async def _add_benign(places: Places, client: KitClient) -> None:
    await client.call_tool("git_add", {"repo_path": _REPO, "files": ["."]})


async def _diff_staged_benign(places: Places, client: KitClient) -> None:
    await client.call_tool("git_diff_staged", {"repo_path": _REPO})


_BENIGN: tuple[FixCheckExploit, ...] = (_add_benign, _diff_staged_benign)

FIXTURES = (
    _fixture("CVE-2026-27735", "git_27735"),
    _fixture("MINI-mch8-8h85-3j5v", "git_mch8"),
)
