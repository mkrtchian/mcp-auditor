from typing import Any

from evals.cve_places import PlantKind
from evals.holdout_kit.kit_client import KitResponse, KitTool
from evals.nuisance_fix_checks import cve_2026_7400_geekgod_fs as geekgod_fs

COUNTED_TOOL = "read_file_tool"
DECLARED_SCOPE = "/tmp"


class RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self) -> list[KitTool]:
        return []

    async def call_tool(self, name: str, args: dict[str, Any]) -> KitResponse:
        self.calls.append((name, args))
        return KitResponse(content="", is_error=False)


async def _calls_of(callables: tuple[Any, ...]) -> list[tuple[str, dict[str, Any]]]:
    client = RecordingClient()
    for call in callables:
        await call(None, client)
    return client.calls


def test_the_witness_is_a_file_sharing_the_scope_s_textual_prefix_without_being_inside_it():
    path = geekgod_fs.WITNESS.coordinates.path

    assert geekgod_fs.WITNESS.kind is PlantKind.FILE
    assert path is not None
    assert path.startswith(DECLARED_SCOPE)
    assert not path.startswith(f"{DECLARED_SCOPE}/")


def test_the_target_pairs_the_vulnerable_and_patched_images():
    target = geekgod_fs.TARGET

    assert target.vulnerable_service == "geekgod-fs-vuln"
    assert target.patched_service == "geekgod-fs"
    assert target.server_patched_service is None


async def test_the_exploit_reads_the_sibling_prefix_file_through_the_counted_tool_only():
    [(tool, arguments)] = await _calls_of(geekgod_fs.TARGET.exploits)

    assert tool == COUNTED_TOOL
    assert geekgod_fs.AIM.search(str(arguments["path"]))


async def test_the_benign_call_reads_inside_the_declared_scope_and_escapes_nothing():
    [(tool, arguments)] = await _calls_of(geekgod_fs.TARGET.benign_calls)

    assert tool == COUNTED_TOOL
    assert str(arguments["path"]).startswith(f"{DECLARED_SCOPE}/")
    assert not geekgod_fs.AIM.search(str(arguments["path"]))
