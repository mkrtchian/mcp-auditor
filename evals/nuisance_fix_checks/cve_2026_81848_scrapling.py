"""scrapling-fetch-mcp fix-check fixture: CVE-2026-81848 (`file://` local file read).

`s_fetch_page`/`s_fetch_pattern` (`mcp.py`) pass the caller's `url` straight into scrapling's
`browse_url` (`_fetcher.py`), which hands it to curl_cffi; curl_cffi honours `file://` exactly as
libcurl does, so `url="file:///<witness>"` reads an arbitrary file the server's user can read and
returns it as fetched page content: a `read_outside_scope` flaw, not the internal_fetch/SSRF-to-
internal-address class the CVE's CWE-918 tag suggests. The fix (0.2.4, advisory-named "0.2.3",
never published to PyPI) adds `_require_web_url`, which allowlists the http/https scheme ahead of
`browse_url` in both tool implementations, rejecting `file://` before it reaches the fetcher.

Both tools are a general-purpose web fetcher with no bounded scope of their own, so the benign
call needs a web target to fetch. A loopback `http.server` is baked into both images (the
`adb-mcp` baked-stub precedent) rather than giving the launch real network egress, so the fixture
stays deterministic and closed (`has_network=False`).
"""

import re
from collections.abc import Generator
from contextlib import contextmanager

from evals.cve_grammar import MechanismClass
from evals.cve_places import Coordinates, Place, Places, PlantKind
from evals.cve_planting import (
    DockerPlanting,
    PlantingHost,
    PlantingSpec,
    SymbolicUser,
    confinement_args,
    planted,
)
from evals.holdout_kit.fix_check import FixCheckTarget
from evals.holdout_kit.kit_client import KitClient
from evals.holdout_kit.kit_launch import Launch, LaunchShape

WITNESS_ID = "scrapling-81848-file"
FILE_PATH = "/opt/app-data/credentials.txt"

AIM = re.compile(r"file://")
HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)

WITNESS = Place(
    id=WITNESS_ID,
    family="local_file_read",
    reachable_by=frozenset({"arbitrary_read"}),
    kind=PlantKind.FILE,
    coordinates=Coordinates(PlantKind.FILE, path=FILE_PATH),
)


@contextmanager
def fetch_env(
    image: str, spec: PlantingSpec, shape: LaunchShape = LaunchShape.NORMAL
) -> Generator[Launch]:
    """No scope argument (a FastMCP stdio server) and no `/srv` layout: the witness file is
    bind-mounted directly by `planted()`. The benign web target (loopback:8080) is baked into the
    image, so the launch needs no network and no sentinel."""
    with planted(spec, image, DockerPlanting()) as args:
        yield Launch(
            command="docker",
            args=["run", "-i", "--rm", *confinement_args(), *args.run_args(), image],
        )


async def exploit_page(places: Places, client: KitClient) -> None:
    path = places[WITNESS_ID].coordinates.path
    await client.call_tool("s_fetch_page", {"url": f"file://{path}", "mode": "basic"})


async def exploit_pattern(places: Places, client: KitClient) -> None:
    path = places[WITNESS_ID].coordinates.path
    await client.call_tool(
        "s_fetch_pattern",
        {"url": f"file://{path}", "search_pattern": "MCPAUDIT", "mode": "basic"},
    )


async def benign_page(places: Places, client: KitClient) -> None:
    await client.call_tool("s_fetch_page", {"url": "http://127.0.0.1:8080/", "mode": "basic"})


async def benign_pattern(places: Places, client: KitClient) -> None:
    await client.call_tool(
        "s_fetch_pattern",
        {"url": "http://127.0.0.1:8080/", "search_pattern": "benign", "mode": "basic"},
    )


TARGET = FixCheckTarget(
    flaw="CVE-2026-81848",
    mechanism=MechanismClass.READ_OUTSIDE_SCOPE,
    aim=AIM,
    witness=WITNESS,
    planting_host=HOST,
    builder=fetch_env,
    exploits=(exploit_page, exploit_pattern),
    benign_calls=(benign_page, benign_pattern),
    vulnerable_service="scrapling-vuln",
    patched_service="scrapling",
    server_patched_service=None,
)

TARGETS = (TARGET,)
