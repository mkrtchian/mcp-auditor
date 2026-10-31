from typing import Any

from evals.holdout_kit.kit_client import KitResponse, KitTool
from evals.nuisance_fix_checks import cve_2025_53100_codehooks as codehooks

COUNTED_TOOL = "query_collection"


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
    target = codehooks.TARGET

    assert target.vulnerable_service == "codehooks-vuln"
    assert target.patched_service == "codehooks"
    assert target.server_patched_service is None


async def test_the_exploit_injects_the_witness_through_the_counted_tool_only():
    [(tool, arguments)] = await _calls_of(codehooks.TARGET.exploits)

    assert tool == COUNTED_TOOL
    assert codehooks.AIM.search(str(arguments["collection"]))


async def test_the_benign_call_stays_clean():
    [(tool, arguments)] = await _calls_of(codehooks.TARGET.benign_calls)

    assert tool == COUNTED_TOOL
    assert not codehooks.AIM.search(str(arguments))
