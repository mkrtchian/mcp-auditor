"""The nuisance `gate` command: what it refuses or reports before any audit, and the
recording messages around a gate run that audits nothing. No Docker, no LLM."""

from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_admission_given as admission
import tests.unit.support.test_nuisance_admission_records_given as records_given
import tests.unit.support.test_run_nuisance_gate_given as given
from evals import run_nuisance
from evals.baseline import BaselineStatus
from tests.unit.support.test_nuisance_admission_edits_given import without_stdio


def test_gate_without_an_admission_exits_zero_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    given.without_any_llm_key(monkeypatch)
    missing = tmp_path / "absent.json"

    exit_code = run_nuisance.main(
        ["gate", *given.gate_arguments(tmp_path, admission.a_census(), missing)]
    )

    assert exit_code == 0
    assert "no acceptance server is admitted" in capsys.readouterr().out


def test_gate_with_only_a_non_current_server_admitted_exits_zero_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    given.without_any_llm_key(monkeypatch)
    path = admission.written(tmp_path, admission.an_admission())

    exit_code = run_nuisance.main(
        [
            "gate",
            *given.gate_arguments(tmp_path, admission.a_census_with_an_acceptance_server(), path),
        ]
    )

    assert exit_code == 0
    assert "no acceptance server is admitted" in capsys.readouterr().out


def test_gate_with_no_admitted_server_able_to_launch_exits_zero_naming_why(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    given.without_any_llm_key(monkeypatch)
    admitted = admission.admitting_the_acceptance_server()
    path = admission.written(tmp_path, without_stdio(admitted, given.GATE_SERVER))

    exit_code = run_nuisance.main(
        [
            "gate",
            *given.gate_arguments(tmp_path, admission.a_census_with_an_acceptance_server(), path),
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "no acceptance server is admitted" not in out
    assert "no admitted acceptance server can run in the gate" in out
    assert f"{given.GATE_SERVER}: does not run over stdio" in out


def test_gate_on_a_server_outside_the_gate_set_exits_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    given.without_any_llm_key(monkeypatch)
    path = admission.written(tmp_path, admission.admitting_the_acceptance_server())
    gate_set = given.gate_arguments(tmp_path, admission.a_census_with_an_acceptance_server(), path)

    exit_code = run_nuisance.main(["gate", *gate_set, "--server", "npm:other"])

    assert exit_code == 2
    assert "unknown gate server: npm:other" in capsys.readouterr().err


def test_gate_refuses_a_server_with_an_unrecorded_field_before_any_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.UNCONFIRMED)
    unrecorded = records_given.with_every_new_field_unrecorded(
        admission.admitting_the_acceptance_server()
    )
    gate_set = given.a_gate_set_of_one_server(tmp_path, unrecorded)

    exit_code = run_nuisance.main(["gate", *gate_set])

    out = capsys.readouterr().out
    assert exit_code == run_nuisance.REFUSED_EXIT
    assert f"{given.GATE_SERVER}: real_software (1 tool)" in out
    assert not (tmp_path / "nuisance_gate_report.json").exists()


def test_gate_refuses_only_the_selected_servers_with_an_unrecorded_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    output = given.a_captured_console(monkeypatch)
    given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.UNCONFIRMED)
    gate_set = given.a_gate_set_beside_an_unrecorded_server(tmp_path)

    selected_recorded = run_nuisance.main(["gate", "--server", given.GATE_SERVER, *gate_set])
    selected_unrecorded = run_nuisance.main(
        ["gate", "--server", given.OTHER_GATE_SERVER, *gate_set]
    )

    assert selected_recorded == 0
    assert selected_unrecorded == run_nuisance.REFUSED_EXIT
    assert f"{given.OTHER_GATE_SERVER}: real_software" in output.getvalue()


def test_the_gate_audits_only_the_selected_servers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    seen = given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.UNCONFIRMED)
    gate_set = given.a_gate_set_beside_an_unrecorded_server(tmp_path)

    run_nuisance.main(["gate", "--server", given.GATE_SERVER, *gate_set])

    assert [s.server_package for s in seen.options.servers] == [given.GATE_SERVER]
    assert seen.options.gate_packages == {given.GATE_SERVER, given.OTHER_GATE_SERVER}


def test_an_exploratory_gate_recording_names_the_command_that_confirms_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    output = given.a_captured_console(monkeypatch)
    given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.UNCONFIRMED)
    gate_set = given.a_gate_set_of_one_server(tmp_path)

    exit_code = run_nuisance.main(["gate", "--record-baseline", *gate_set])

    assert exit_code == 0
    assert (
        "Run uv run python -m evals.run_nuisance gate --record-baseline again now, at this commit"
        " and on these images, to confirm it. Commit evals/baselines/nuisance/ by hand once"
        " confirmed."
    ) in output.getvalue()


def test_the_confirming_gate_command_repeats_the_server_and_a_non_default_run_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    output = given.a_captured_console(monkeypatch)
    given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.UNCONFIRMED)
    gate_set = given.a_gate_set_of_one_server(tmp_path)
    server = given.GATE_SERVER

    run_nuisance.main(["gate", "--record-baseline", "--server", server, "--runs", "5", *gate_set])

    assert (
        "Run uv run python -m evals.run_nuisance gate --record-baseline"
        f" --server {server} --runs 5 again now"
    ) in output.getvalue()


def test_the_confirming_gate_command_leaves_the_default_run_count_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    output = given.a_captured_console(monkeypatch)
    given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.UNCONFIRMED)
    gate_set = given.a_gate_set_of_one_server(tmp_path)

    run_nuisance.main(["gate", "--record-baseline", "--runs", "3", *gate_set])

    printed = output.getvalue()
    assert "Run uv run python -m evals.run_nuisance gate --record-baseline again now" in printed
    assert "--runs" not in printed


def test_a_recorded_gate_baseline_prints_once_after_the_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    output = given.a_captured_console(monkeypatch)
    given.a_green_recording_writing(monkeypatch, tmp_path, BaselineStatus.CONFIRMED)
    gate_set = given.a_gate_set_of_one_server(tmp_path)

    run_nuisance.main(["gate", "--record-baseline", *gate_set])

    printed = output.getvalue()
    assert printed.count("recorded (confirmed)") == 1
    assert printed.index("Gate green.") < printed.index("Baseline recorded (confirmed)")
    assert "Commit evals/baselines/nuisance/ by hand." in printed
    assert "again now" not in printed
