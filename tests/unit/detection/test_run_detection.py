import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from evals.cve.detection.command_deps import DetectionCommandDeps
from evals.cve.detection.session import run_gated
from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.cve.images import image_tag
from evals.cve.launch_audit import RunOverrides
from evals.cve.run_images import target_services
from evals.detection_preflight import preflight_ok
from evals.gate_outcome import CRASHED_EXIT
from tests.unit.detection.support import run_detection_cli as cli
from tests.unit.detection.support import test_run_detection_given as given
from tests.unit.support.acceptance_targets import an_acceptance_target


def test_a_failed_preflight_exits_as_a_crash_before_the_session_starts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    deps, received = given.a_session_recording_options(monkeypatch)

    code = cli.exit_code_of(
        replace(deps, preflight=lambda: False), "--no-baseline", "--report", str(tmp_path / "r")
    )

    assert code == 4
    assert received == []


def test_a_recording_from_a_dirty_tree_is_refused_as_not_comparable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
):
    deps = replace(cli.a_session_under_priced_models(monkeypatch, dirty=True), session=run_gated)

    code = cli.exit_code_of(deps, "--record-baseline", "--report", str(tmp_path / "r.json"))

    assert code == 3
    assert "record from a clean tree" in " ".join(capsys.readouterr().out.split())


@pytest.mark.parametrize("unpriced", ["MCP_AUDITOR_MODEL", "MCP_AUDITOR_JUDGE_MODEL"])
def test_a_measurement_run_with_an_unpriced_model_is_refused_before_any_audit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, unpriced: str
):
    deps = replace(
        cli.a_session_under_priced_models(monkeypatch),
        session=given.a_session_that_crashes_if_started,
    )
    monkeypatch.setenv(unpriced, "an-unpriced-model")
    report_path = tmp_path / "detection_report.json"

    code = cli.exit_code_of(deps, "--no-baseline", "--chains", "3", "--report", str(report_path))

    assert code == 3
    assert not report_path.exists()


def test_a_no_baseline_run_with_priced_models_reports_a_cost_per_billed_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    deps = cli.a_session_under_priced_models(monkeypatch)
    report_path = tmp_path / "detection_report.json"

    cli.exit_code_of(deps, "--no-baseline", "--report", str(report_path))

    report = json.loads(report_path.read_text())
    assert [cost["flaw_id"] for cost in report["costs"]] == [cli.BILLED_FLAW]
    assert report["prices_as_of"] is not None
    assert report["measurement"] is None


def test_a_measurement_run_forces_its_settings_on_the_audit_and_records_them(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    forced: list[object] = []
    deps = replace(
        cli.a_session_under_priced_models(monkeypatch),
        audit_target=given.an_audit_target_recording(forced),
    )
    report_path = tmp_path / "detection_report.json"

    cli.exit_code_of(
        deps, "--no-baseline", "--chains", "3", "--no-tools-filter", "--report", str(report_path)
    )

    assert forced == [RunOverrides(3, None, None, audit_every_tool=True)]
    measurement = json.loads(report_path.read_text())["measurement"]
    assert (measurement["chains"], measurement["every_tool"]) == (3, True)


def test_a_calibration_check_that_cannot_reach_docker_exits_as_a_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("PATH", str(tmp_path))  # no docker binary to find
    deps = replace(cli.deps_reaching_nothing(), preflight=preflight_ok)

    assert cli.exit_code_of(deps, "--calibration-check") == 4


def test_a_calibration_check_that_raises_exits_as_a_crash():
    assert cli.exit_code_of(given.a_calibration_check(raises=True), "--calibration-check") == 4


def test_a_survey_that_raises_exits_as_a_crash():
    assert cli.exit_code_of(given.a_survey(raises=True), "--survey") == 4


def test_the_survey_surveys_every_target_and_exits_zero():
    surveyed: list[str] = []

    code = cli.exit_code_of(given.a_survey(surveyed=surveyed), "--survey")

    assert code == 0
    assert sorted(surveyed) == sorted(target.flaw_id for target in ACCEPTANCE_TARGETS)


@pytest.mark.parametrize("mode", [given.a_calibration_check, given.a_survey])
@pytest.mark.parametrize("raises", [False, True])
def test_a_maintainer_mode_removes_the_containers_left_running_even_when_it_raises(
    mode: Callable[..., DetectionCommandDeps], raises: bool
):
    containers = cli.a_sweep_finding("leftover_filesystem")
    flag = "--calibration-check" if mode is given.a_calibration_check else "--survey"

    cli.exit_code_of(mode(sweep=containers, raises=raises), flag, "--flaw", cli.RECORDED_FLAW)

    assert containers.removed == ["leftover_filesystem"]
    assert containers.listed_tags == [_tags_of(cli.RECORDED_FLAW)]


def test_a_graded_run_removes_the_containers_of_its_images_left_running(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    containers = cli.a_sweep_finding("leftover_filesystem")
    deps = replace(cli.a_session_under_priced_models(monkeypatch), sweep=containers.sweep)
    report = str(tmp_path / "r.json")

    cli.exit_code_of(deps, "--no-baseline", "--flaw", cli.RECORDED_FLAW, "--report", report)

    assert containers.removed == ["leftover_filesystem"]
    assert containers.listed_tags == [_tags_of(cli.RECORDED_FLAW)]


def test_a_graded_run_that_crashes_still_removes_the_containers_left_running(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    containers = cli.a_sweep_finding("leftover_filesystem")
    deps = replace(
        cli.a_session_under_priced_models(monkeypatch),
        sweep=containers.sweep,
        session=given.a_session_that_crashes_if_started,
    )

    code = cli.exit_code_of(deps, "--no-baseline", "--report", str(tmp_path / "r.json"))

    assert code == 4
    assert containers.removed == ["leftover_filesystem"]


def test_a_fatal_provider_error_prints_the_crash_panel_without_its_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
):
    deps = replace(
        cli.a_session_under_priced_models(monkeypatch),
        session=given.a_session_raising_a_fatal_provider_error,
    )

    code = cli.exit_code_of(deps, "--no-baseline", "--report", str(tmp_path / "r.json"))

    printed = capsys.readouterr()
    assert code == CRASHED_EXIT
    assert "PermissionError" in printed.out
    assert "sk-secret" not in printed.out + printed.err


def _tags_of(flaw_id: str) -> list[str]:
    return [image_tag(service) for service in target_services([an_acceptance_target(flaw_id)])]


def test_a_graded_run_reports_the_tree_it_ran_on_and_the_tokens_billed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    deps = cli.a_session_under_priced_models(monkeypatch, dirty=True)
    report_path = tmp_path / "detection_report.json"

    cli.exit_code_of(deps, "--no-baseline", "--report", str(report_path))

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
    flags: list[str], expected: list[str]
):
    checked: list[str] = []

    code = cli.exit_code_of(
        given.a_calibration_check(checked=checked), "--calibration-check", *flags
    )

    assert code == 0
    assert checked == expected


def test_the_no_baseline_flag_reaches_the_session(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    deps, received = given.a_session_recording_options(monkeypatch)

    code = cli.exit_code_of(deps, "--no-baseline", "--report", str(tmp_path / "r.json"))

    assert code == 0
    assert [options.no_baseline for options in received] == [True]
