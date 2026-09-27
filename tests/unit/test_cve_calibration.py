import re
from dataclasses import dataclass

import pytest

from evals.cve_calibration import RecordingClient, dead_conditions
from evals.cve_grammar import MechanismClass
from evals.cve_units import unit_of_exchanges
from mcp_auditor.domain import ToolResponse
from tests.fakes.mcp_client import FakeMCPClient

NONCE = "MCPAUDIT-0123456789abcdef"
ID_OUTPUT = "uid=65534(nobody) gid=65534(nogroup)"
INJECTED = {"command": "version; id; echo $FLAG"}
PLAIN = {"command": "version"}


@dataclass(frozen=True)
class FakeTarget:
    mechanism: MechanismClass
    sentinel: str
    aim: re.Pattern[str]


COMMAND_TARGET = FakeTarget(MechanismClass.COMMAND_EXECUTION, NONCE, re.compile(r"[;&|`]|\$\("))


async def test_recording_client_passes_response_through_and_records_the_exchange():
    flag_response = ToolResponse(content="the flag")
    client = FakeMCPClient(tools=[], responses={"git_diff_staged": flag_response})
    recorder = RecordingClient(client)

    response = await recorder.call_tool("git_diff_staged", {"repo_path": "/work/secret"})

    assert response is flag_response
    assert recorder.exchanges == [("git_diff_staged", {"repo_path": "/work/secret"}, flag_response)]


@pytest.mark.parametrize(
    ("exploit", "benign", "conditions"),
    [
        ((INJECTED, f"{ID_OUTPUT}\n{NONCE}"), (PLAIN, "Client Version: v1"), []),
        (
            (INJECTED, NONCE),
            (PLAIN, "Client Version: v1"),
            ["exploit surfaces no computed_output proof"],
        ),
        ((PLAIN, f"{ID_OUTPUT}\n{NONCE}"), (PLAIN, "Client Version: v1"), ["exploit not aimed"]),
        (
            (INJECTED, f"{ID_OUTPUT}\n{NONCE}"),
            (PLAIN, f"leaked {NONCE}"),
            ["negative control: benign call surfaces planted_nonce"],
        ),
        (
            (INJECTED, f"{ID_OUTPUT}\n{NONCE}"),
            ({"command": "version; true"}, "Client Version: v1"),
            ["negative control: benign call reads as aimed"],
        ),
    ],
    ids=[
        "live",
        "missing_proof_kind",
        "exploit_not_aimed",
        "benign_surfaces_a_proof",
        "benign_aimed",
    ],
)
def test_dead_conditions_name_each_failed_condition(
    exploit: tuple[dict[str, str], str],
    benign: tuple[dict[str, str], str],
    conditions: list[str],
):
    result = dead_conditions(
        COMMAND_TARGET, unit_of_exchanges([exploit]), unit_of_exchanges([benign])
    )

    assert result == conditions
