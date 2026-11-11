"""scrapling-fetch-mcp fix-check fixture: CVE-2026-81848 (`file://` local file read).

`s_fetch_page`/`s_fetch_pattern` (`mcp.py`) pass the caller's `url` straight into scrapling's
`browse_url` (`_fetcher.py`), which hands it to curl_cffi; curl_cffi honours `file://` exactly as
libcurl does, so `url="file:///<witness>"` reads an arbitrary file the server's user can read and
returns it as fetched page content: a `read_outside_scope` flaw, not the internal_fetch/SSRF-to-
internal-address class the CVE's CWE-918 tag suggests. The fix (0.2.4, advisory-named "0.2.3",
never published to PyPI) adds `_require_web_url`, which allowlists the http/https scheme ahead of
`browse_url` in both tool implementations, rejecting `file://` before it reaches the fetcher.

Both tools are a general-purpose web fetcher with no bounded scope of their own, so the benign
call needs a web target to fetch: example.com, the host the server's README names in its usage
examples, served under its real name by the stand-in from its capture
(`evals/stand_ins/example.com.json`) on the holder's closed network, rather than a site written
for the fixture and baked into the images (`has_network=False`, no egress).
"""

import re
from collections.abc import Generator
from contextlib import contextmanager

from evals.cve.kit.client import KitClient
from evals.cve.kit.fix_check import FixCheckFixture
from evals.cve.kit.launch import Launch, LaunchShape
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
from evals.cve_planting_base import PublicNames

WITNESS_ID = "scrapling-81848-file"
FILE_PATH = "/opt/app-data/credentials.txt"

AIM = re.compile(r"file://")
HOST = PlantingHost(
    SymbolicUser.UNPRIVILEGED,
    "/",
    has_network=False,
    public_names=PublicNames(stand_ins=("example.com",), trust=("SSL_CERT_FILE",)),
)

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
    bind-mounted directly by `planted()`. The web page the benign calls fetch is example.com,
    served under its real name by the stand-in `planted()` starts from its capture, with the
    fixture authority trusted through SSL_CERT_FILE (curl_cffi reads it)."""
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
    await client.call_tool("s_fetch_page", {"url": "https://example.com/", "mode": "basic"})


async def benign_pattern(places: Places, client: KitClient) -> None:
    await client.call_tool(
        "s_fetch_pattern",
        {"url": "https://example.com/", "search_pattern": "permission", "mode": "basic"},
    )


FIXTURE = FixCheckFixture(
    flaw="CVE-2026-81848",
    effect_class=MechanismClass.READ_OUTSIDE_SCOPE,
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

FIXTURES = (FIXTURE,)
