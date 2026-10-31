from typing import Any

from evals.holdout_kit.kit_client import KitResponse, KitTool
from evals.nuisance_fix_checks import cve_2026_4198_auto_commit as auto_commit

COUNTED_TOOL = "git-changes-commit-message"


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
    target = auto_commit.TARGET

    assert target.vulnerable_service == "auto-commit-vuln"
    assert target.patched_service == "auto-commit"
    assert target.server_patched_service is None


async def test_the_exploits_inject_cat_flag_through_the_counted_tool_only():
    calls = await _calls_of(auto_commit.TARGET.exploits)

    assert {tool for tool, _ in calls} == {COUNTED_TOOL}
    assert all(auto_commit.AIM.search(str(arguments["autoCommitPath"])) for _, arguments in calls)


async def test_the_benign_call_stays_clean():
    [(tool, arguments)] = await _calls_of(auto_commit.TARGET.benign_calls)

    assert tool == COUNTED_TOOL
    assert not auto_commit.AIM.search(str(arguments))
