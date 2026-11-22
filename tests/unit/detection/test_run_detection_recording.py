from pathlib import Path

import pytest

from evals.baseline import BaselineStatus
from tests.unit.detection.support import run_detection_cli as cli
from tests.unit.detection.support import test_run_detection_recording_given as given


def test_an_unconfirmed_recording_names_the_command_that_confirms_it(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    output = given.a_captured_console(capsys, monkeypatch)
    deps = given.a_recording_session_writing(monkeypatch, BaselineStatus.UNCONFIRMED)

    cli.exit_code_of(deps, "--record-baseline", "--report", str(tmp_path / "r.json"))

    assert (
        "Run uv run python -m evals.run_detection --record-baseline again now, at this commit"
        " and on these images, to confirm it. Commit evals/baselines/detection/ by hand once"
        " confirmed."
    ) in output.getvalue()


def test_the_confirming_command_repeats_the_target_filter_and_a_non_default_run_count(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    output = given.a_captured_console(capsys, monkeypatch)
    deps = given.a_recording_session_writing(monkeypatch, BaselineStatus.UNCONFIRMED)
    report = str(tmp_path / "r.json")

    cli.exit_code_of(
        deps,
        "--record-baseline",
        "--flaw",
        cli.RECORDED_FLAW,
        "--runs",
        "5",
        "--report",
        report,
    )

    assert (
        "Run uv run python -m evals.run_detection --record-baseline"
        f" --flaw {cli.RECORDED_FLAW} --runs 5 again now"
    ) in output.getvalue()


def test_the_confirming_command_leaves_the_default_run_count_and_budget_out(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    output = given.a_captured_console(capsys, monkeypatch)
    deps = given.a_recording_session_writing(monkeypatch, BaselineStatus.UNCONFIRMED)
    report = str(tmp_path / "r.json")

    cli.exit_code_of(deps, "--record-baseline", "--runs", "3", "--report", report)

    assert "--runs" not in output.getvalue()
    assert "--budget" not in output.getvalue()


def test_a_confirmed_recording_says_to_commit_the_baseline(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    output = given.a_captured_console(capsys, monkeypatch)
    deps = given.a_recording_session_writing(monkeypatch, BaselineStatus.CONFIRMED)

    cli.exit_code_of(deps, "--record-baseline", "--report", str(tmp_path / "r.json"))

    assert "Commit evals/baselines/detection/ by hand." in output.getvalue()
    assert "again now" not in output.getvalue()


def test_a_recording_prints_the_outcome_once_before_the_recorded_baselines(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    output = given.a_captured_console(capsys, monkeypatch)
    deps = given.a_recording_session_writing(monkeypatch, BaselineStatus.UNCONFIRMED)

    cli.exit_code_of(deps, "--record-baseline", "--report", str(tmp_path / "r.json"))

    printed = output.getvalue()
    assert printed.count("Gate green.") == 1
    assert "Gate:" not in printed
    assert printed.index("Gate green.") < printed.index("Baseline recorded (unconfirmed)")
