from typing import Any

from evals.holdout_kit.kit_client import KitResponse, KitTool
from evals.nuisance_fix_checks import cve_2026_7446_semgrep as semgrep

COUNTED_TOOL = "scan_directory"


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
    target = semgrep.TARGET

    assert target.vulnerable_service == "semgrep-vuln"
    assert target.patched_service == "semgrep"
    assert target.server_patched_service is None


async def test_the_exploit_injects_cat_flag_through_the_counted_tool_only():
    [(tool, arguments)] = await _calls_of(semgrep.TARGET.exploits)

    assert tool == COUNTED_TOOL
    assert semgrep.AIM.search(str(arguments["path"]))


async def test_the_benign_call_stays_clean():
    [(tool, arguments)] = await _calls_of(semgrep.TARGET.benign_calls)

    assert tool == COUNTED_TOOL
    assert not semgrep.AIM.search(str(arguments))
