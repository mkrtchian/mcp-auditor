"""praisonai fix-check fixture: CVE-2026-47394 (workflow.show absolute-path escape).

praisonai.workflow.show (mcp_server/adapters/cli_tools.py) opens the caller-supplied file_path
directly (``open(file_path, 'r')``) with no containment check at all on 4.6.33/4.6.34, so an
absolute path reaches any file the process can read and its content comes back verbatim. The
4.6.40 fix (_resolve_cwd_yaml_path) rejects any file_path containing a path separator, a leading
dot, or missing a .yaml/.yml suffix, and resolves what remains strictly inside the current
working directory before reading it: an absolute path such as the one below is rejected before
the file is ever touched.

The exploit's file_path is the absolute-path marker itself (the aim); the benign call, a bare
"agents.yaml" filename with no separator, reads the README's first agents.yaml sample, seeded at
/agents.yaml in the working directory /: 4.6.40 resolves it inside the working directory and
4.6.33 opens it relative to it, so both versions answer with the sample's text.

praisonai.workflow.validate and praisonai.deploy.validate, which the advisory also names and which
open the caller's path on the vulnerable version, are left out of this flaw's tools: no admission
record writes their fields or plays a benign call for them (docs/nuisance-log.md).
"""

import re

from evals.cve.grammar import FlawClass
from evals.cve.kit.client import KitClient
from evals.cve.kit.fix_check import FixCheckFixture
from evals.cve.kit.launch import command_injection_env
from evals.cve.places import Coordinates, Place, PlaceKind, Places
from evals.cve.planting import PlantingHost, SymbolicUser

AIM = re.compile(r"^/")
HOST = PlantingHost(SymbolicUser.UNPRIVILEGED, "/", has_network=False)

WITNESS = Place(
    id="praisonai-workflow-escape",
    family="fix_check",
    reaches=frozenset({"arbitrary_read"}),
    kind=PlaceKind.FILE,
    coordinates=Coordinates(PlaceKind.FILE, path="/flag"),
)
_BENIGN_FILE_PATH = "agents.yaml"


async def _exploit_workflow_show(places: Places, client: KitClient) -> None:
    await client.call_tool("praisonai.workflow.show", {"file_path": "/flag"})


async def _benign_workflow_show(places: Places, client: KitClient) -> None:
    await client.call_tool("praisonai.workflow.show", {"file_path": _BENIGN_FILE_PATH})


FIXTURE = FixCheckFixture(
    flaw="CVE-2026-47394",
    effect_class=FlawClass.READ_OUTSIDE_SCOPE,
    aim=AIM,
    witness=WITNESS,
    planting_host=HOST,
    builder=command_injection_env,
    exploits=(_exploit_workflow_show,),
    benign_calls=(_benign_workflow_show,),
    vulnerable_service="praisonai-vuln",
    patched_service="praisonai",
    server_patched_service=None,
)

FIXTURES = (FIXTURE,)
