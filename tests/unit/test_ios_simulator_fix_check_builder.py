from typing import Any

from evals.cve_places import PlantKind
from evals.nuisance_fix_checks import cve_2025_52573_ios_simulator as ios


class _RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(self, name: str, args: dict[str, Any]) -> None:
        self.calls.append((name, args))


async def _record(exploit: Any) -> tuple[str, dict[str, Any]]:
    client = _RecordingClient()
    await exploit({ios.WITNESS.id: ios.WITNESS}, client)
    assert len(client.calls) == 1
    return client.calls[0]


def test_the_witness_is_a_file_at_the_flag_path():
    assert ios.WITNESS.kind is PlantKind.FILE
    assert ios.WITNESS.coordinates.path == "/flag"


async def test_each_exploit_udid_carries_the_aim():
    for exploit in ios.TARGET.exploits:
        _, args = await _record(exploit)
        assert ios.AIM.search(args["udid"])


async def test_no_benign_call_carries_the_aim():
    for benign in ios.TARGET.benign_calls:
        _, args = await _record(benign)
        assert not any(ios.AIM.search(str(value)) for value in args.values())


async def test_the_exploits_call_the_two_counted_tools():
    tools = {(await _record(exploit))[0] for exploit in ios.TARGET.exploits}
    assert tools == {"ui_describe_all", "ui_describe_point"}
