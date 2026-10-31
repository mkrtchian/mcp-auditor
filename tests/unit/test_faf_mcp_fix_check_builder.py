from typing import Any

from evals.holdout_kit.kit_client import KitResponse, KitTool
from evals.nuisance_fix_checks import ghsa_j4r7_8ph4_43g3_faf as faf_mcp

COUNTED_TOOL = "faf_read"


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
    target = faf_mcp.TARGET

    assert target.vulnerable_service == "faf-mcp-vuln"
    assert target.patched_service == "faf-mcp"
    assert target.server_patched_service is None


async def test_the_exploit_reads_outside_the_faf_scope_through_the_counted_tool_only():
    [(tool, arguments)] = await _calls_of(faf_mcp.TARGET.exploits)

    assert tool == COUNTED_TOOL
    assert faf_mcp.AIM.search(str(arguments["path"]))


async def test_the_benign_call_stays_inside_the_faf_scope_and_escapes_nothing():
    [(tool, arguments)] = await _calls_of(faf_mcp.TARGET.benign_calls)

    assert tool == COUNTED_TOOL
    assert str(arguments["path"]).startswith("/work/")
    assert not faf_mcp.AIM.search(str(arguments["path"]))
