"""The holdout `run` command around its orchestrator: no drawn target, the refusals before the run,
the result file written before the report, and a run stopped by an exception. No Docker, no LLM."""

import dataclasses
import json
from pathlib import Path

import pytest

import tests.unit.detection.support.holdout_command_deps as command_deps
import tests.unit.detection.support.test_run_detection_holdout_run_given as given
from evals import run_detection_holdout
from evals.cve.detection.holdout_run import run_holdout_targets
from evals.cve.provider_errors import ProviderFatal
from evals.cve.run_files import RunInterrupted
from tests.unit.support import holdout_result_keys


def test_run_without_a_drawn_target_exits_zero_and_says_so(capsys: pytest.CaptureFixture[str]):
    deps = dataclasses.replace(command_deps.a_drawn_run_reaching_nothing(), drawn=())

    exit_code = run_detection_holdout.main(["run"], deps)

    assert exit_code == 0
    assert "no holdout target is drawn" in capsys.readouterr().out


def test_run_refuses_when_tracing_is_on(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "true")

    exit_code = run_detection_holdout.main(["run"], command_deps.a_command_reaching_nothing())

    assert exit_code == run_detection_holdout.REFUSED_EXIT


def test_run_refuses_an_acceptance_target_for_its_tools_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    command_deps.a_ready_run(monkeypatch)
    deps = dataclasses.replace(
        command_deps.a_drawn_run_through(run_holdout_targets),
        drawn=(command_deps.a_drawn_target(),),
    )
    census = command_deps.a_census_with_a_ready_card(tmp_path)

    exit_code = run_detection_holdout.main(["run", "--census", str(census)], deps)

    assert exit_code == run_detection_holdout.REFUSED_EXIT
    assert (
        f"the rule runs with no tools filter, but {command_deps.DRAWN_FLAW} carries one"
        in capsys.readouterr().out
    )


@pytest.mark.parametrize("suffix", [".json", ".md", ".result.json"])
def test_run_refuses_an_existing_report_file_before_any_dep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], suffix: str
):
    command_deps.a_ready_run(monkeypatch)
    report = tmp_path / "holdout_report.json"
    report.with_suffix(suffix).write_text("kept")

    exit_code = run_detection_holdout.main(
        ["run", "--report", str(report)], command_deps.a_command_reaching_nothing()
    )

    assert exit_code == run_detection_holdout.REFUSED_EXIT
    assert "--report" in capsys.readouterr().out


def test_run_refuses_a_drawn_target_whose_card_is_not_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    command_deps.a_ready_run(monkeypatch)
    census = given.a_census_with_no_draw(tmp_path)
    report = tmp_path / "holdout_report.json"

    exit_code = run_detection_holdout.main(
        ["run", "--report", str(report), "--census", str(census)],
        command_deps.a_drawn_run_reaching_nothing(),
    )

    assert exit_code == run_detection_holdout.REFUSED_EXIT
    out = capsys.readouterr().out
    assert f"{command_deps.DRAWN_FLAW}: no draw record" in out
    assert "not ready under detection suite rule v11" in out
    assert not report.with_suffix(".result.json").exists()


def test_run_writes_the_report_beside_its_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    command_deps.a_ready_run(monkeypatch)
    report = tmp_path / "holdout_report.json"

    exit_code = run_detection_holdout.main(
        _run_flags(tmp_path, report),
        command_deps.a_drawn_run_ending_in(command_deps.a_run_result()),
    )

    assert exit_code == 0
    assert report.exists()
    assert report.with_suffix(".md").exists()
    assert not json.loads(report.with_suffix(".result.json").read_text())["partial"]


def test_the_result_and_the_report_carry_the_glossary_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    command_deps.a_ready_run(monkeypatch)
    report = tmp_path / "holdout_report.json"

    run_detection_holdout.main(
        _run_flags(tmp_path, report),
        command_deps.a_drawn_run_ending_in(command_deps.a_run_result()),
    )

    result_keys = holdout_result_keys.result_keys(report.with_suffix(".result.json"))
    report_keys = holdout_result_keys.result_keys(report)
    assert {"flaw_id", "class_labels", "missed_call_causes"} <= result_keys
    assert {
        "holdout_detection_rate",
        "flaw_id",
        "class_labels",
        "missed_call_causes",
    } <= report_keys


def test_run_writes_its_result_before_the_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    command_deps.a_ready_run(monkeypatch)
    deps = dataclasses.replace(
        command_deps.a_drawn_run_ending_in(command_deps.a_run_result()),
        write_report=given.a_failing_report_write,
    )
    report = tmp_path / "holdout_report.json"

    with pytest.raises(RuntimeError, match="the report failed to write"):
        run_detection_holdout.main(_run_flags(tmp_path, report), deps)

    result = report.with_suffix(".result.json")
    assert holdout_result_keys.result_keys(result).isdisjoint(holdout_result_keys.PROOF_FIELDS)
    assert not report.exists()


def test_a_fatal_provider_error_exits_four_keeping_the_partial_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    command_deps.a_ready_run(monkeypatch)
    partial = dataclasses.replace(command_deps.a_run_result(), partial=True)
    fatal = ProviderFatal(PermissionError("the key sk-secret was revoked"))
    report = tmp_path / "holdout_report.json"

    exit_code = run_detection_holdout.main(
        _run_flags(tmp_path, report),
        command_deps.a_drawn_run_ending_in(RunInterrupted(partial, fatal)),
    )

    out = capsys.readouterr().out
    assert exit_code == run_detection_holdout.CRASHED_EXIT
    assert "PermissionError" in out
    assert "sk-secret" not in out
    assert json.loads(report.with_suffix(".result.json").read_text())["partial"]
    assert not report.exists()


def test_any_other_interruption_is_raised_keeping_the_partial_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    command_deps.a_ready_run(monkeypatch)
    partial = dataclasses.replace(command_deps.a_run_result(), partial=True)
    deps = command_deps.a_drawn_run_ending_in(RunInterrupted(partial, KeyError("a bug")))
    report = tmp_path / "holdout_report.json"

    with pytest.raises(KeyError):
        run_detection_holdout.main(_run_flags(tmp_path, report), deps)

    assert json.loads(report.with_suffix(".result.json").read_text())["partial"]


def test_a_value_error_out_of_the_run_is_no_malformed_census(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    command_deps.a_ready_run(monkeypatch)
    deps = command_deps.a_drawn_run_ending_in(ValueError("a bug in the run"))

    with pytest.raises(ValueError, match="a bug in the run"):
        run_detection_holdout.main(_run_flags(tmp_path, tmp_path / "holdout_report.json"), deps)


def _run_flags(tmp_path: Path, report: Path) -> list[str]:
    census = command_deps.a_census_with_a_ready_card(tmp_path)
    return ["run", "--report", str(report), "--census", str(census)]
