import json
from collections.abc import Callable
from pathlib import Path

import pytest

from evals import run_detection
from evals.cve.detection.audit import RunOverrides
from evals.cve.detection.measurement import MEASUREMENT_NEEDS_NO_BASELINE, STEPS_WITHOUT_CHAINS
from evals.cve.detection.targets import ACCEPTANCE_TARGETS, image_tag
from evals.cve.run_images import target_services
from tests.unit.detection.support import run_detection_cli as cli
from tests.unit.detection.support import test_run_detection_given as given
from tests.unit.support.acceptance_targets import an_acceptance_target


@pytest.fixture(autouse=True)
def _no_docker_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    cli.a_sweep_finding(monkeypatch)


@pytest.mark.parametrize(
    "flags",
    [
        ["--record-baseline", "--no-baseline"],
        ["--calibration-check", "--no-baseline"],
        ["--calibration-check", "--record-baseline"],
        ["--survey", "--calibration-check"],
        ["--survey", "--record-baseline"],
        ["--survey", "--no-baseline"],
    ],
)
def test_incompatible_flags_are_refused_as_not_comparable(
    monkeypatch: pytest.MonkeyPatch, flags: list[str]
):
    assert cli.exit_code_of(monkeypatch, *flags) == 3


@pytest.mark.parametrize(
    "flags",
    [
        ["--chains", "3"],
        ["--chain-steps", "3"],
        ["--tool-call-timeout", "30"],
        ["--no-tools-filter"],
        ["--record-baseline", "--tool-call-timeout", "30"],
    ],
)
def test_a_measurement_flag_outside_a_no_baseline_run_is_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], flags: list[str]
):
    code = cli.exit_code_of(monkeypatch, *flags)

    assert code == 3
    assert MEASUREMENT_NEEDS_NO_BASELINE in " ".join("".join(capsys.readouterr()).split())


@pytest.mark.parametrize(
    "flags",
    [
        ["--no-baseline", "--chain-steps", "3"],
        ["--no-baseline", "--chains", "0", "--chain-steps", "3"],
    ],
)
def test_chain_steps_without_chains_are_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], flags: list[str]
):
    code = cli.exit_code_of(monkeypatch, *flags)

    assert code == 3
    assert STEPS_WITHOUT_CHAINS in " ".join("".join(capsys.readouterr()).split())


@pytest.mark.parametrize("mode", ["--calibration-check", "--survey"])
def test_a_measurement_flag_on_a_mode_that_runs_no_audit_is_refused_for_that_reason(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], mode: str
):
    code = cli.exit_code_of(monkeypatch, mode, "--chains", "3")

    assert code == 3
    assert "run no audit" in "".join(capsys.readouterr())


def test_a_negative_chain_count_is_refused_by_the_parser(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    code = cli.exit_code_of(monkeypatch, "--no-baseline", "--chains", "-1")

    assert code == 2
    assert "--chains: expected at least 0" in capsys.readouterr().err


@pytest.mark.parametrize("unpriced", ["MCP_AUDITOR_MODEL", "MCP_AUDITOR_JUDGE_MODEL"])
def test_a_measurement_run_with_an_unpriced_model_is_refused_before_any_audit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, unpriced: str
):
    cli.a_session_under_priced_models(monkeypatch)
    monkeypatch.setenv(unpriced, "an-unpriced-model")
    monkeypatch.setattr(run_detection, "run_gated", given.a_session_that_crashes_if_started)
    report_path = tmp_path / "detection_report.json"

    code = cli.exit_code_of(
        monkeypatch, "--no-baseline", "--chains", "3", "--report", str(report_path)
    )

    assert code == 3
    assert not report_path.exists()


def test_a_no_baseline_run_with_priced_models_reports_a_cost_per_billed_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    cli.a_session_under_priced_models(monkeypatch)
    report_path = tmp_path / "detection_report.json"

    cli.exit_code_of(monkeypatch, "--no-baseline", "--report", str(report_path))

    report = json.loads(report_path.read_text())
    assert [cost["flaw_id"] for cost in report["costs"]] == [cli.BILLED_FLAW]
    assert report["prices_as_of"] is not None
    assert report["measurement"] is None


def test_a_measurement_run_forces_its_settings_on_the_audit_and_records_them(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    forced: list[object] = []
    cli.a_session_under_priced_models(monkeypatch, given.an_audit_target_recording(forced))
    report_path = tmp_path / "detection_report.json"

    cli.exit_code_of(
        monkeypatch,
        "--no-baseline",
        "--chains",
        "3",
        "--no-tools-filter",
        "--report",
        str(report_path),
    )

    assert forced == [RunOverrides(3, None, None, audit_every_tool=True)]
    measurement = json.loads(report_path.read_text())["measurement"]
    assert (measurement["chains"], measurement["every_tool"]) == (3, True)


def test_a_calibration_that_cannot_reach_docker_exits_as_a_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("PATH", str(tmp_path))  # no docker binary to find

    assert cli.exit_code_of(monkeypatch, "--calibration-check") == 4


def test_a_calibration_that_raises_exits_as_a_crash(monkeypatch: pytest.MonkeyPatch):
    given.a_calibration(monkeypatch, raises=True)

    assert cli.exit_code_of(monkeypatch, "--calibration-check") == 4


def test_a_survey_that_raises_exits_as_a_crash(monkeypatch: pytest.MonkeyPatch):
    given.a_survey(monkeypatch, raises=True)

    assert cli.exit_code_of(monkeypatch, "--survey") == 4


@pytest.mark.parametrize("mode", [given.a_calibration, given.a_survey])
@pytest.mark.parametrize("raises", [False, True])
def test_a_maintainer_mode_removes_the_containers_left_running_even_when_it_raises(
    monkeypatch: pytest.MonkeyPatch, mode: Callable[..., None], raises: bool
):
    containers = cli.a_sweep_finding(monkeypatch, "leftover_filesystem")
    mode(monkeypatch, raises=raises)
    flag = "--calibration-check" if mode is given.a_calibration else "--survey"

    cli.exit_code_of(monkeypatch, flag, "--flaw", cli.RECORDED_FLAW)

    assert containers.removed == ["leftover_filesystem"]
    assert containers.listed_tags == [_tags_of(cli.RECORDED_FLAW)]


def test_a_graded_run_removes_the_containers_of_its_images_left_running(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    containers = cli.a_sweep_finding(monkeypatch, "leftover_filesystem")
    cli.a_session_under_priced_models(monkeypatch)
    report = str(tmp_path / "r.json")

    cli.exit_code_of(monkeypatch, "--no-baseline", "--flaw", cli.RECORDED_FLAW, "--report", report)

    assert containers.removed == ["leftover_filesystem"]
    assert containers.listed_tags == [_tags_of(cli.RECORDED_FLAW)]


def test_a_graded_run_that_crashes_still_removes_the_containers_left_running(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    containers = cli.a_sweep_finding(monkeypatch, "leftover_filesystem")
    cli.a_session_under_priced_models(monkeypatch)
    monkeypatch.setattr(run_detection, "run_gated", given.a_session_that_crashes_if_started)

    code = cli.exit_code_of(monkeypatch, "--no-baseline", "--report", str(tmp_path / "r.json"))

    assert code == 4
    assert containers.removed == ["leftover_filesystem"]


def _tags_of(flaw_id: str) -> list[str]:
    return [image_tag(service) for service in target_services([an_acceptance_target(flaw_id)])]


def test_a_concurrency_below_one_is_refused_by_the_parser(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    code = cli.exit_code_of(monkeypatch, "--concurrency", "0")

    assert code == 2
    assert "--concurrency: expected at least 1" in capsys.readouterr().err


def test_a_graded_run_reports_the_tree_it_ran_on_and_the_tokens_billed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    cli.a_session_under_priced_models(monkeypatch, dirty=True)
    report_path = tmp_path / "detection_report.json"

    cli.exit_code_of(monkeypatch, "--no-baseline", "--report", str(report_path))

    report = json.loads(report_path.read_text())
    assert (report["commit"], report["dirty"]) == ("c0ffee", True)
    assert report["provider_usage"]["input_tokens"] == 500


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        ([], [target.flaw_id for target in ACCEPTANCE_TARGETS]),
        (["--flaw", cli.RECORDED_FLAW], [cli.RECORDED_FLAW]),
    ],
)
def test_the_calibration_check_runs_on_every_target_or_on_the_flaws_named(
    monkeypatch: pytest.MonkeyPatch, flags: list[str], expected: list[str]
):
    checked: list[str] = []
    given.a_calibration(monkeypatch, checked=checked)

    code = cli.exit_code_of(monkeypatch, "--calibration-check", *flags)

    assert code == 0
    assert checked == expected


def test_the_no_baseline_flag_reaches_the_session(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    received = given.a_session_recording_options(monkeypatch)

    code = cli.exit_code_of(monkeypatch, "--no-baseline", "--report", str(tmp_path / "r.json"))

    assert code == 0
    assert [options.no_baseline for options in received] == [True]
