import json
from pathlib import Path

import pytest

from evals import run_cve_benchmark
from evals.baseline import BaselineStatus
from evals.cve_audit import RunOverrides
from evals.cve_measurement import MEASUREMENT_UNGATED, STEPS_WITHOUT_CHAINS
from tests.unit.support import test_run_cve_benchmark_given as given


@pytest.mark.parametrize(
    "flags",
    [
        ["--record-baseline", "--ungated"],
        ["--calibrate", "--ungated"],
        ["--calibrate", "--record-baseline"],
        ["--survey", "--calibrate"],
        ["--survey", "--record-baseline"],
        ["--survey", "--ungated"],
    ],
)
def test_incompatible_flags_are_refused_as_not_comparable(
    monkeypatch: pytest.MonkeyPatch, flags: list[str]
):
    assert given.exit_code_of(monkeypatch, *flags) == 3


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
def test_a_measurement_flag_outside_an_ungated_run_is_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], flags: list[str]
):
    code = given.exit_code_of(monkeypatch, *flags)

    assert code == 3
    assert MEASUREMENT_UNGATED in " ".join("".join(capsys.readouterr()).split())


@pytest.mark.parametrize(
    "flags",
    [
        ["--ungated", "--chain-steps", "3"],
        ["--ungated", "--chains", "0", "--chain-steps", "3"],
    ],
)
def test_chain_steps_without_chains_are_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], flags: list[str]
):
    code = given.exit_code_of(monkeypatch, *flags)

    assert code == 3
    assert STEPS_WITHOUT_CHAINS in " ".join("".join(capsys.readouterr()).split())


@pytest.mark.parametrize("mode", ["--calibrate", "--survey"])
def test_a_measurement_flag_on_a_mode_that_runs_no_audit_is_refused_for_that_reason(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], mode: str
):
    code = given.exit_code_of(monkeypatch, mode, "--chains", "3")

    assert code == 3
    assert "run no audit" in "".join(capsys.readouterr())


def test_a_negative_chain_count_is_refused_by_the_parser(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    code = given.exit_code_of(monkeypatch, "--ungated", "--chains", "-1")

    assert code == 2
    assert "--chains: expected at least 0" in capsys.readouterr().err


@pytest.mark.parametrize("unpriced", ["MCP_AUDITOR_MODEL", "MCP_AUDITOR_JUDGE_MODEL"])
def test_a_measurement_run_with_an_unpriced_model_is_refused_before_any_audit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, unpriced: str
):
    given.a_session_under_priced_models(monkeypatch)
    monkeypatch.setenv(unpriced, "an-unpriced-model")
    monkeypatch.setattr(run_cve_benchmark, "run_gated", given.a_session_that_crashes_if_started)
    report_path = tmp_path / "cve_report.json"

    code = given.exit_code_of(
        monkeypatch, "--ungated", "--chains", "3", "--report", str(report_path)
    )

    assert code == 3
    assert not report_path.exists()


def test_an_ungated_run_with_priced_models_reports_a_cost_per_billed_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    given.a_session_under_priced_models(monkeypatch)
    report_path = tmp_path / "cve_report.json"

    given.exit_code_of(monkeypatch, "--ungated", "--report", str(report_path))

    report = json.loads(report_path.read_text())
    assert [cost["cve_id"] for cost in report["costs"]] == [given.BILLED_CVE]
    assert report["prices_as_of"] is not None
    assert report["measurement"] is None


def test_a_measurement_run_forces_its_settings_on_the_audit_and_records_them(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    forced: list[object] = []
    given.a_session_under_priced_models(monkeypatch, given.an_audit_target_recording(forced))
    report_path = tmp_path / "cve_report.json"

    given.exit_code_of(
        monkeypatch, "--ungated", "--chains", "3", "--no-tools-filter", "--report", str(report_path)
    )

    assert forced == [RunOverrides(3, None, None, audit_every_tool=True)]
    measurement = json.loads(report_path.read_text())["measurement"]
    assert (measurement["chains"], measurement["every_tool"]) == (3, True)


def test_a_calibration_that_cannot_reach_docker_exits_as_a_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("PATH", str(tmp_path))  # no docker binary to find

    assert given.exit_code_of(monkeypatch, "--calibrate") == 4


def test_a_calibration_that_raises_exits_as_a_crash(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(run_cve_benchmark, "preflight_ok", lambda: True)

    async def boom(*_args: object, **_kwargs: object) -> bool:
        raise ValueError("a kept id with no record")

    monkeypatch.setattr(run_cve_benchmark, "calibrate_all", boom)

    assert given.exit_code_of(monkeypatch, "--calibrate") == 4


def test_a_survey_that_raises_exits_as_a_crash(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(run_cve_benchmark, "preflight_ok", lambda: True)

    async def boom(*_args: object, **_kwargs: object) -> None:
        raise ValueError("a kept id with no record")

    monkeypatch.setattr(run_cve_benchmark, "survey_all", boom)

    assert given.exit_code_of(monkeypatch, "--survey") == 4


def test_a_concurrency_below_one_is_refused_by_the_parser(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    code = given.exit_code_of(monkeypatch, "--concurrency", "0")

    assert code == 2
    assert "--concurrency: expected at least 1" in capsys.readouterr().err


def test_a_graded_run_reports_the_tree_it_ran_on_and_the_tokens_billed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    given.a_session_under_priced_models(monkeypatch, dirty=True)
    report_path = tmp_path / "cve_report.json"

    given.exit_code_of(monkeypatch, "--ungated", "--report", str(report_path))

    report = json.loads(report_path.read_text())
    assert (report["commit"], report["dirty"]) == ("c0ffee", True)
    assert report["provider_usage"]["input_tokens"] == 500


def test_an_exploratory_recording_names_the_command_that_confirms_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    output = given.a_captured_console(monkeypatch)
    given.a_recording_session_writing(monkeypatch, BaselineStatus.EXPLORATORY)

    given.exit_code_of(monkeypatch, "--record-baseline", "--report", str(tmp_path / "r.json"))

    assert (
        "Run uv run python -m evals.run_cve_benchmark --record-baseline again now, at this commit"
        " and on these images, to confirm it. Commit evals/baselines/cve/ by hand once confirmed."
    ) in output.getvalue()


def test_the_confirming_command_repeats_the_target_filter_and_a_non_default_run_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    output = given.a_captured_console(monkeypatch)
    given.a_recording_session_writing(monkeypatch, BaselineStatus.EXPLORATORY)
    report = str(tmp_path / "r.json")

    given.exit_code_of(
        monkeypatch,
        "--record-baseline",
        "--cve",
        given.RECORDED_CVE,
        "--runs",
        "5",
        "--report",
        report,
    )

    assert (
        "Run uv run python -m evals.run_cve_benchmark --record-baseline"
        f" --cve {given.RECORDED_CVE} --runs 5 again now"
    ) in output.getvalue()


def test_the_confirming_command_leaves_the_default_run_count_and_budget_out(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    output = given.a_captured_console(monkeypatch)
    given.a_recording_session_writing(monkeypatch, BaselineStatus.EXPLORATORY)
    report = str(tmp_path / "r.json")

    given.exit_code_of(monkeypatch, "--record-baseline", "--runs", "3", "--report", report)

    assert "--runs" not in output.getvalue()
    assert "--budget" not in output.getvalue()


def test_a_confirmed_recording_says_to_commit_the_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    output = given.a_captured_console(monkeypatch)
    given.a_recording_session_writing(monkeypatch, BaselineStatus.CONFIRMED)

    given.exit_code_of(monkeypatch, "--record-baseline", "--report", str(tmp_path / "r.json"))

    assert "Commit evals/baselines/cve/ by hand." in output.getvalue()
    assert "again now" not in output.getvalue()


def test_a_recording_prints_the_verdict_once_before_the_recorded_baselines(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    output = given.a_captured_console(monkeypatch)
    given.a_recording_session_writing(monkeypatch, BaselineStatus.EXPLORATORY)

    given.exit_code_of(monkeypatch, "--record-baseline", "--report", str(tmp_path / "r.json"))

    printed = output.getvalue()
    assert printed.count("Gate green.") == 1
    assert "Gate:" not in printed
    assert printed.index("Gate green.") < printed.index("Baseline recorded (exploratory)")
