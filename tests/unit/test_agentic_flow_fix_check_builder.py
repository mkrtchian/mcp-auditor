from typing import Any

from evals.holdout_kit.kit_client import KitResponse, KitTool
from evals.nuisance_fix_checks import cve_2026_58195_agentic_flow as agentic_flow

COUNTED_TOOL = "agentic_flow_agent_info"


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
    target = agentic_flow.TARGET

    assert target.vulnerable_service == "agentic-flow-vuln"
    assert target.patched_service == "agentic-flow"
    assert target.server_patched_service is None


async def test_the_exploit_injects_cat_flag_through_the_counted_tool_only():
    [(tool, arguments)] = await _calls_of(agentic_flow.TARGET.exploits)

    assert tool == COUNTED_TOOL
    assert agentic_flow.AIM.search(str(arguments["name"]))


async def test_the_benign_call_stays_clean():
    [(tool, arguments)] = await _calls_of(agentic_flow.TARGET.benign_calls)

    assert tool == COUNTED_TOOL
    assert not agentic_flow.AIM.search(str(arguments))
