"""The nuisance `run` command around its orchestrator: the report refusal, the result file
written before the report, and a run stopped by an exception. No Docker, no LLM."""

import dataclasses
import json
from pathlib import Path

import pytest

import tests.unit.support.test_run_nuisance_run_given as given
from evals import run_nuisance
from evals.nuisance_results import RunInterrupted
from evals.provider_errors import ProviderFatal
from tests.unit.support.test_run_holdout_run_given import PROOF_FIELDS, result_keys


@pytest.mark.parametrize("suffix", [".json", ".md", ".result.json"])
def test_run_refuses_an_existing_report_file_before_any_dep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], suffix: str
):
    given.a_run_reaching_nothing(monkeypatch)
    report = tmp_path / "nuisance_report.json"
    report.with_suffix(suffix).write_text("kept")

    exit_code = run_nuisance.main(["run", "--report", str(report)])

    assert exit_code == run_nuisance.REFUSED_EXIT
    assert "--report" in capsys.readouterr().out


def test_run_writes_the_report_beside_its_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    given.an_admitted_run_ending_in(monkeypatch, given.a_run_result())
    report = tmp_path / "nuisance_report.json"

    assert run_nuisance.main(given.a_run_command(tmp_path)) == 0

    assert report.exists()
    assert report.with_suffix(".md").exists()
    assert not json.loads(report.with_suffix(".result.json").read_text())["partial"]


def test_run_writes_its_result_before_the_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    given.an_admitted_run_ending_in(monkeypatch, given.a_run_result())

    def failing_report(*_: object) -> object:
        raise RuntimeError("the report failed to build")

    monkeypatch.setattr(run_nuisance, "build_report", failing_report)
    report = tmp_path / "nuisance_report.json"

    with pytest.raises(RuntimeError, match="the report failed to build"):
        run_nuisance.main(given.a_run_command(tmp_path))

    result = report.with_suffix(".result.json")
    assert result_keys(result).isdisjoint(PROOF_FIELDS)
    assert not report.exists()


def test_a_fatal_provider_error_exits_four_keeping_the_partial_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    partial = dataclasses.replace(given.a_run_result(), partial=True)
    fatal = ProviderFatal(PermissionError("the key sk-secret was revoked"))
    given.an_admitted_run_ending_in(monkeypatch, RunInterrupted(partial, fatal))
    report = tmp_path / "nuisance_report.json"

    exit_code = run_nuisance.main(given.a_run_command(tmp_path))

    out = capsys.readouterr().out
    assert exit_code == run_nuisance.CRASHED_EXIT
    assert "PermissionError" in out
    assert "sk-secret" not in out
    assert json.loads(report.with_suffix(".result.json").read_text())["partial"]
    assert not report.exists()


def test_any_other_interruption_is_raised_keeping_the_partial_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    partial = dataclasses.replace(given.a_run_result(), partial=True)
    given.an_admitted_run_ending_in(monkeypatch, RunInterrupted(partial, KeyError("a bug")))
    report = tmp_path / "nuisance_report.json"

    with pytest.raises(KeyError):
        run_nuisance.main(given.a_run_command(tmp_path))

    assert json.loads(report.with_suffix(".result.json").read_text())["partial"]


def test_a_value_error_out_of_the_run_is_no_malformed_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    given.an_admitted_run_ending_in(monkeypatch, ValueError("a bug in the run"))

    with pytest.raises(ValueError, match="a bug in the run"):
        run_nuisance.main(given.a_run_command(tmp_path))
