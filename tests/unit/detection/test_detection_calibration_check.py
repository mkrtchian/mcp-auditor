import dataclasses
import io
import re
from dataclasses import dataclass

import pytest

import tests.unit.detection.support.test_detection_calibration_check_given as given
from evals.cve.detection.calibration_check import (
    CheckOptions,
    check_target,
    passes_calibration_check,
    report_launch_error,
)
from evals.cve.detection.targets import TargetVersion
from evals.cve.failure_text import FULL_DETAIL, TYPES_ONLY
from evals.cve.grammar import FlawClass
from evals.cve.kit.driver import not_fixed_reasons, not_live_reasons
from evals.cve.units import unit_of_exchanges
from tests.unit.support.captured_console import a_captured_console

NONCE = "MCPAUDIT-0123456789abcdef"
ID_OUTPUT = "uid=65534(nobody) gid=65534(nogroup)"
INJECTED = {"command": "version; id; echo $FLAG"}
PLAIN = {"command": "version"}
LAUNCH_FAILURE = ExceptionGroup(
    "unhandled errors", [ExceptionGroup("nested", [ConnectionError("Connection closed")])]
)


@dataclass(frozen=True)
class FakeTarget:
    classes: frozenset[FlawClass]
    nonces: dict[str, str]
    aim: re.Pattern[str]


COMMAND_TARGET = FakeTarget(
    frozenset({FlawClass.COMMAND_EXECUTION}), {"planted": NONCE}, re.compile(r"[;&|`]|\$\(")
)
NO_PLACE_TARGET = dataclasses.replace(COMMAND_TARGET, nonces={})


async def test_an_unknown_kept_id_raises_out_of_the_calibration_check_before_any_launch():
    target = dataclasses.replace(given.a_target(), kept_places=("no-such-place",))

    with pytest.raises(ValueError, match="no-such-place"):
        await passes_calibration_check(target, {})


async def test_check_target_hands_the_ping_answer_of_each_version_to_its_callback():
    launches = given.launches({TargetVersion.VULNERABLE: True, TargetVersion.PATCHED: False})
    answers: list[tuple[TargetVersion, bool]] = []

    reasons = await check_target(
        given.a_target(),
        given.a_places_mapping(),
        CheckOptions(
            on_ping=lambda version, answered: answers.append((version, answered)),
            connect=launches.connect,
        ),
    )

    assert reasons == []
    assert answers == [(TargetVersion.VULNERABLE, True), (TargetVersion.PATCHED, False)]


async def test_a_patched_exploit_missing_a_required_argument_is_out_of_calibration():
    launches = given.launches_whose_patched_read_requires("file")

    reasons = await check_target(
        given.a_target(), given.a_places_mapping(), CheckOptions(connect=launches.connect)
    )

    assert reasons == [
        "patched: exploit 0 (read) lacks file, which the schema requires, and the SDK rejects"
        " every call of it at argument validation, so it never reaches the patched code"
    ]


async def test_a_patched_exploit_call_to_an_unlisted_tool_is_printed_and_fails_nothing(
    capsys: pytest.CaptureFixture[str],
):
    launches = given.launches_listing_only_on_the_patched_version("write")

    passes = await passes_calibration_check(
        given.a_target(), given.a_places_mapping(), CheckOptions(connect=launches.connect)
    )

    assert passes
    output = " ".join(capsys.readouterr().out.split())
    assert f"{given.FLAW_ID} patched: exploit 0 calls read, which this version does not list" in (
        output
    )


async def test_the_exploit_responses_print_on_both_versions_only_when_asked(
    capsys: pytest.CaptureFixture[str],
):
    launches = given.launches()
    options = CheckOptions(connect=launches.connect, show_exploit_responses=True)

    await passes_calibration_check(given.a_target(), given.a_places_mapping(), options)
    await passes_calibration_check(
        given.a_target(), given.a_places_mapping(), CheckOptions(connect=launches.connect)
    )

    output = capsys.readouterr().out
    shown = [line for line in output.splitlines() if "exploit 0, tool exchanges" in line]
    assert shown == [
        f"{given.FLAW_ID} vulnerable version exploit 0, tool exchanges:",
        f"{given.FLAW_ID} patched version exploit 0, tool exchanges:",
    ]


async def test_check_target_without_a_callback_sends_no_ping():
    launches = given.launches()

    reasons = await check_target(
        given.a_target(), given.a_places_mapping(), CheckOptions(connect=launches.connect)
    )

    assert reasons == []
    assert launches.pings == 0


async def test_the_calibration_check_prints_whether_each_version_answers_the_ping(
    capsys: pytest.CaptureFixture[str],
):
    launches = given.launches({TargetVersion.VULNERABLE: False, TargetVersion.PATCHED: True})

    passes = await passes_calibration_check(
        given.a_target(), given.a_places_mapping(), CheckOptions(connect=launches.connect)
    )

    output = capsys.readouterr().out
    assert passes
    assert f"{given.FLAW_ID} vulnerable version answers the ping: no" in output
    assert f"{given.FLAW_ID} patched version answers the ping: yes" in output


async def test_a_target_out_of_calibration_that_answers_the_ping_still_fails(
    capsys: pytest.CaptureFixture[str],
):
    launches = given.launches(exploit_surfaces_the_nonce=False)

    passes = await passes_calibration_check(
        given.a_target(), given.a_places_mapping(), CheckOptions(connect=launches.connect)
    )

    output = capsys.readouterr().out
    assert not passes
    assert f"{given.FLAW_ID} vulnerable version answers the ping: yes" in output
    assert "exploit surfaces no nonce for fict-flag" in output


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
def test_not_live_reasons_name_each_failed_condition(
    exploit: tuple[dict[str, str], str],
    benign: tuple[dict[str, str], str],
    conditions: list[str],
):
    result = not_live_reasons(
        COMMAND_TARGET, [unit_of_exchanges([exploit])], unit_of_exchanges([benign])
    )

    assert result == conditions


def test_a_target_that_keeps_no_place_is_out_of_calibration():
    result = not_live_reasons(
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
def test_not_fixed_reasons_name_a_surviving_flaw_or_an_erroring_benign_call(
    exploit: tuple[dict[str, str], str], benign_errored: bool, conditions: list[str]
):
    result = not_fixed_reasons(COMMAND_TARGET, [unit_of_exchanges([exploit])], benign_errored)

    assert result == conditions


def test_a_launch_error_under_full_detail_prints_its_root_cause_after_its_label(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)

    report_launch_error("CVE-EXITS check error", LAUNCH_FAILURE, io.StringIO("boom\n"), FULL_DETAIL)

    assert output.getvalue().splitlines() == [
        "CVE-EXITS check error: ConnectionError: Connection closed",
        "  boom",
    ]


def test_a_launch_error_under_types_only_prints_no_server_text(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)

    report_launch_error("CVE-EXITS check error", LAUNCH_FAILURE, io.StringIO("boom\n"), TYPES_ONLY)

    assert output.getvalue().splitlines() == ["CVE-EXITS check error: ConnectionError"]
