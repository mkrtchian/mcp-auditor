from typing import Any

from evals.holdout_kit.kit_client import KitResponse, KitTool
from evals.nuisance_fix_checks import cve_2025_67366_sylphxltd_filesystem as sylphxltd

COUNTED_TOOL = "read_content"


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


def test_the_target_pairs_the_vulnerable_and_patched_images():
    target = sylphxltd.TARGET

    assert target.vulnerable_service == "sylphxltd-filesystem-vuln"
    assert target.patched_service == "sylphxltd-filesystem"
    assert target.server_patched_service is None


async def test_the_exploit_follows_the_baked_symlink_through_the_counted_tool_only():
    [(tool, arguments)] = await _calls_of(sylphxltd.TARGET.exploits)

    assert tool == COUNTED_TOOL
    assert sylphxltd.AIM.search(str(arguments["paths"]))


async def test_the_benign_call_reads_a_plain_file_and_follows_no_symlink():
    [(tool, arguments)] = await _calls_of(sylphxltd.TARGET.benign_calls)

    assert tool == COUNTED_TOOL
    assert not sylphxltd.AIM.search(str(arguments))
