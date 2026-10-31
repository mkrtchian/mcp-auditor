"""Unit coverage for evals/nuisance_fix_checks/cve_2025_53107_git_mcp.py: the service triple of
each FixCheckTarget, the exploit argument each flaw's AIM must match, and that the benign calls
stay clean of the exploit's own argument.
"""

from typing import Any

from evals.holdout_kit.kit_client import KitResponse, KitTool
from evals.nuisance_fix_checks.cve_2025_53107_git_mcp import T_53107, T_85626


class _RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self) -> list[KitTool]:
        return []

    async def call_tool(self, name: str, args: dict[str, Any]) -> KitResponse:
        self.calls.append((name, args))
        return KitResponse("", is_error=False)


def test_53107_service_triple_sets_the_server_as_the_later_patched_arm():
    assert T_53107.vulnerable_service == "git-mcp-flaw-2.1.4"
    assert T_53107.patched_service == "git-mcp-flaw-2.1.5"
    assert T_53107.server_patched_service == "git-mcp"


def test_85626_service_triple_has_no_server_patched_arm():
    assert T_85626.vulnerable_service == "git-mcp-flaw-2.15.1"
    assert T_85626.patched_service == "git-mcp"
    assert T_85626.server_patched_service is None


async def test_53107_exploit_calls_git_add_with_an_argument_matching_its_aim():
    client = _RecordingClient()
    await T_53107.exploits[0]({}, client)

    assert len(client.calls) == 1
    name, arguments = client.calls[0]
    assert name == "git_add"
    assert T_53107.aim.search(str(arguments["files"]))


async def test_85626_exploit_calls_git_diff_with_no_index():
    client = _RecordingClient()
    await T_85626.exploits[0]({}, client)

    assert len(client.calls) == 1
    name, arguments = client.calls[0]
    assert name == "git_diff"
    assert arguments["source"] == "--no-index"
    assert T_85626.aim.search(str(arguments["source"]))


async def test_53107_benign_call_does_not_match_the_exploit_aim():
    client = _RecordingClient()
    await T_53107.benign_calls[0]({}, client)

    name, arguments = client.calls[0]
    assert name == "git_add"
    assert not T_53107.aim.search(str(arguments))


async def test_85626_benign_call_does_not_match_the_exploit_aim():
    client = _RecordingClient()
    await T_85626.benign_calls[0]({}, client)

    name, arguments = client.calls[0]
    assert name == "git_diff"
    assert "source" not in arguments
