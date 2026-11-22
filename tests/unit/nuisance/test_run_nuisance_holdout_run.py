"""The nuisance `run` command around its orchestrator: the report refusal, the result file
written before the report, and a run stopped by an exception. No Docker, no LLM."""

import dataclasses
import json
from pathlib import Path

import pytest

import tests.unit.nuisance.admission.support.test_nuisance_admission_given as admission_given
import tests.unit.nuisance.admission.support.test_nuisance_admission_records_given as records_given
import tests.unit.nuisance.support.test_run_nuisance_holdout_run_given as given
from evals import run_nuisance
from evals.cve.nuisance.holdout_run import NUISANCE_RUNS
from evals.cve.nuisance.results import RunInterrupted
from evals.cve.provider_errors import ProviderFatal
from tests.unit.detection.support.test_run_detection_holdout_run_given import (
    PROOF_FIELDS,
    result_keys,
)
from tests.unit.nuisance.admission.support import (
    test_nuisance_holdout_calibration_copies_given as copies_given,
)
from tests.unit.support.admission_mutations import admitting


@pytest.mark.parametrize("suffix", [".json", ".md", ".result.json"])
def test_run_refuses_an_existing_report_file_before_any_dep(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], suffix: str
):
    deps = given.a_run_reaching_nothing()
    report = tmp_path / "nuisance_report.json"
    report.with_suffix(suffix).write_text("kept")

    exit_code = run_nuisance.main(["run", "--report", str(report)], deps)

    assert exit_code == run_nuisance.REFUSED_EXIT
    assert "--report" in capsys.readouterr().out


def test_run_refuses_a_server_with_an_unrecorded_field_before_its_settings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    deps = given.a_run_refused_before_its_settings()
    unrecorded = records_given.with_every_new_field_unrecorded(admission_given.an_admission())
    command = given.a_run_command(tmp_path, unrecorded)

    exit_code = run_nuisance.main(command, deps)

    out = capsys.readouterr().out
    assert exit_code == run_nuisance.REFUSED_EXIT
    assert f"{admission_given.SERVER_PACKAGE}: real_software (2 tools)" in out
    assert not (tmp_path / "nuisance_report.json").with_suffix(".result.json").exists()


def test_run_refuses_a_holdout_calibration_copy_whose_flaw_left_the_layer_before_its_settings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    deps = given.a_run_refused_before_its_settings()
    stale = copies_given.a_server_with_a_holdout_calibration_copy_at(copies_given.RECORDED)
    admission = admitting(stale)

    exit_code = run_nuisance.main(given.a_run_command(tmp_path, admission), deps)

    words = " ".join(capsys.readouterr().out.replace("│", " ").split())
    assert exit_code == run_nuisance.REFUSED_EXIT
    assert (
        "taken from a fixture that has since changed or left the detection holdout layer" in words
    )
    assert f"{copies_given.COPIED_FLAW} is no longer a drawn holdout target" in words
    assert not (tmp_path / "nuisance_report.json").with_suffix(".result.json").exists()


def test_run_writes_the_report_beside_its_result(tmp_path: Path):
    deps = given.an_admitted_run_ending_in(given.a_run_result())
    report = tmp_path / "nuisance_report.json"

    assert run_nuisance.main(given.a_run_command(tmp_path), deps) == 0

    assert report.exists()
    assert report.with_suffix(".md").exists()
    assert not json.loads(report.with_suffix(".result.json").read_text())["partial"]


def test_run_records_the_census_walk_record_and_admission_commits_in_its_result(tmp_path: Path):
    deps = given.an_admitted_run_keeping_its_provenance()
    report = tmp_path / "nuisance_report.json"

    assert run_nuisance.main(given.a_run_command(tmp_path), deps) == 0

    result = json.loads(report.with_suffix(".result.json").read_text())
    assert result["census_commit"] == "commit-of-census.json"
    assert result["walk_record_commit"] == "commit-of-nuisance_walk_record.json"
    assert result["admission_commit"] == "commit-of-nuisance_admission.json"


def test_run_writes_its_result_before_the_report(tmp_path: Path):
    deps = given.an_admitted_run_failing_its_report_write()
    report = tmp_path / "nuisance_report.json"

    with pytest.raises(RuntimeError, match="the report failed to write"):
        run_nuisance.main(given.a_run_command(tmp_path), deps)

    result = report.with_suffix(".result.json")
    assert result_keys(result).isdisjoint(PROOF_FIELDS)
    assert not report.exists()


def test_a_fatal_provider_error_exits_four_keeping_the_partial_result(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    partial = dataclasses.replace(given.a_run_result(), partial=True)
    fatal = ProviderFatal(PermissionError("the key sk-secret was revoked"))
    deps = given.an_admitted_run_ending_in(RunInterrupted(partial, fatal))
    report = tmp_path / "nuisance_report.json"

    exit_code = run_nuisance.main(given.a_run_command(tmp_path), deps)

    out = capsys.readouterr().out
    assert exit_code == run_nuisance.CRASHED_EXIT
    assert "PermissionError" in out
    assert "sk-secret" not in out
    assert json.loads(report.with_suffix(".result.json").read_text())["partial"]
    assert not report.exists()


def test_any_other_interruption_is_raised_keeping_the_partial_result(tmp_path: Path):
    partial = dataclasses.replace(given.a_run_result(), partial=True)
    deps = given.an_admitted_run_ending_in(RunInterrupted(partial, KeyError("a bug")))
    report = tmp_path / "nuisance_report.json"

    with pytest.raises(KeyError):
        run_nuisance.main(given.a_run_command(tmp_path), deps)

    assert json.loads(report.with_suffix(".result.json").read_text())["partial"]


def test_a_value_error_out_of_the_run_is_no_malformed_input(tmp_path: Path):
    deps = given.an_admitted_run_ending_in(ValueError("a bug in the run"))

    with pytest.raises(ValueError, match="a bug in the run"):
        run_nuisance.main(given.a_run_command(tmp_path), deps)


def test_run_help_gives_the_default_number_of_runs(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit):
        run_nuisance.main(["run", "--help"])

    help_text = " ".join(capsys.readouterr().out.split())
    assert f"default {NUISANCE_RUNS}, lowerable to 1" in help_text
