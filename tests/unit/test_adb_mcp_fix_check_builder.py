from typing import Any

from evals.cve_places import PlantKind
from evals.nuisance_fix_checks import cve_2025_59834_adb_mcp as adb_mcp

COUNTED_TOOLS = frozenset({"adb_install", "adb_logcat", "adb_pull", "adb_push"})


class RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(self, name: str, args: dict[str, Any]) -> None:
        self.calls.append((name, args))


async def _record(exploit: Any) -> tuple[str, dict[str, Any]]:
    client = RecordingClient()
    await exploit({adb_mcp.WITNESS.id: adb_mcp.WITNESS}, client)
    assert len(client.calls) == 1
    return client.calls[0]


def test_the_witness_is_a_file_at_the_flag_path():
    assert adb_mcp.WITNESS.kind is PlantKind.FILE
    assert adb_mcp.WITNESS.coordinates.path == "/flag"


async def test_each_exploit_device_carries_the_aim():
    for exploit in adb_mcp.TARGET.exploits:
        _, args = await _record(exploit)
        assert adb_mcp.AIM.search(args["device"])


async def test_no_benign_call_carries_the_aim():
    for benign in adb_mcp.TARGET.benign_calls:
        _, args = await _record(benign)
        assert not any(adb_mcp.AIM.search(str(value)) for value in args.values())


async def test_the_exploits_call_exactly_the_counted_bounded_tools():
    tools = {(await _record(exploit))[0] for exploit in adb_mcp.TARGET.exploits}
    assert tools == COUNTED_TOOLS


async def test_adb_shell_is_excluded_as_the_runner_tool():
    tools = {(await _record(exploit))[0] for exploit in adb_mcp.TARGET.exploits}
    assert "adb_shell" not in tools


async def test_adb_devices_is_excluded_as_not_injectable():
    tools = {(await _record(exploit))[0] for exploit in adb_mcp.TARGET.exploits}
    assert "adb_devices" not in tools


async def test_every_counted_tool_has_a_benign_call():
    benign_tools = {(await _record(benign))[0] for benign in adb_mcp.TARGET.benign_calls}
    assert benign_tools == COUNTED_TOOLS
