import dataclasses
import re
from dataclasses import dataclass

import pytest

from evals.cve_calibration import (
    RecordingClient,
    calibrate_one,
    dead_conditions,
    patched_dead_conditions,
)
from evals.cve_grammar import MechanismClass
from evals.cve_targets import CVE_TARGETS
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
    nonces: dict[str, str]
    aim: re.Pattern[str]


COMMAND_TARGET = FakeTarget(
    MechanismClass.COMMAND_EXECUTION, {"planted": NONCE}, re.compile(r"[;&|`]|\$\(")
)
NO_PLACE_TARGET = dataclasses.replace(COMMAND_TARGET, nonces={})


async def test_an_unknown_kept_id_raises_out_of_calibrate_one_before_any_launch():
    target = dataclasses.replace(CVE_TARGETS[0], kept_places=("no-such-place",))

    with pytest.raises(ValueError, match="no-such-place"):
        await calibrate_one(target, {})


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
            (INJECTED, ID_OUTPUT),
            (PLAIN, "Client Version: v1"),
            ["exploit surfaces no nonce for planted"],
        ),
        ((PLAIN, f"{ID_OUTPUT}\n{NONCE}"), (PLAIN, "Client Version: v1"), ["exploit 0 not aimed"]),
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
        "exploit_surfaces_no_nonce",
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
        COMMAND_TARGET, [unit_of_exchanges([exploit])], unit_of_exchanges([benign])
    )

    assert result == conditions


def test_a_target_that_keeps_no_place_reads_dead():
    result = dead_conditions(
        NO_PLACE_TARGET,
        [unit_of_exchanges([(INJECTED, ID_OUTPUT)])],
        unit_of_exchanges([(PLAIN, "v1")]),
    )

    assert result == ["keeps no place"]


@pytest.mark.parametrize(
    ("exploit", "benign_errored", "conditions"),
    [
        ((INJECTED, ID_OUTPUT), False, []),
        (
            (INJECTED, f"{ID_OUTPUT}\n{NONCE}"),
            False,
            ["patched: exploit 0 still surfaces planted"],
        ),
        ((INJECTED, ID_OUTPUT), True, ["patched: benign call errored"]),
        (
            (INJECTED, f"{ID_OUTPUT}\n{NONCE}"),
            True,
            ["patched: exploit 0 still surfaces planted", "patched: benign call errored"],
        ),
    ],
    ids=["clean", "still_surfaces", "benign_errored", "both"],
)
def test_patched_dead_conditions_name_a_surviving_flaw_or_an_erroring_benign_call(
    exploit: tuple[dict[str, str], str], benign_errored: bool, conditions: list[str]
):
    result = patched_dead_conditions(COMMAND_TARGET, [unit_of_exchanges([exploit])], benign_errored)

    assert result == conditions
