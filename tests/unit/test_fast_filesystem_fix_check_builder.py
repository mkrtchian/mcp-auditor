"""Unit coverage for evals/nuisance_fix_checks/cve_2026_5327_fast_filesystem.py: the service
triple of the FixCheckTarget, the exploit argument the AIM must match, and that the benign call
stays clean of the exploit's own argument.
"""

from typing import Any

from evals.holdout_kit.kit_client import KitResponse, KitTool
from evals.nuisance_fix_checks.cve_2026_5327_fast_filesystem import TARGET


class _RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self) -> list[KitTool]:
        return []

    async def call_tool(self, name: str, args: dict[str, Any]) -> KitResponse:
        self.calls.append((name, args))
        return KitResponse("", is_error=False)


def test_service_triple_sets_no_server_patched_arm():
    assert TARGET.vulnerable_service == "fast-filesystem-vuln"
    assert TARGET.patched_service == "fast-filesystem"
    assert TARGET.server_patched_service is None


async def test_exploit_calls_get_disk_usage_with_an_argument_matching_its_aim():
    client = _RecordingClient()
    await TARGET.exploits[0]({}, client)

    assert len(client.calls) == 1
    name, arguments = client.calls[0]
    assert name == "fast_get_disk_usage"
    assert TARGET.aim.search(str(arguments["path"]))


async def test_benign_call_does_not_match_the_exploit_aim():
    client = _RecordingClient()
    await TARGET.benign_calls[0]({}, client)

    name, arguments = client.calls[0]
    assert name == "fast_get_disk_usage"
    assert not TARGET.aim.search(str(arguments))
