from pathlib import Path

import pytest

import tests.unit.nuisance.gate.support.test_nuisance_gate_console_given as given
from evals.cve.nuisance.exits import EXIT_REASON_TEXTS
from evals.cve.nuisance.gate.gate_console import print_nuisance_gate_summary
from evals.cve.nuisance.gate.gate_report import GATE_LEGEND
from evals.eval_display import print_outcome
from tests.unit.nuisance.gate.support.nuisance_gate_reports import (
    FLAGGED_IN_BASELINE,
    NOT_ADMITTED,
    OUTSIDE,
)
from tests.unit.nuisance.gate.support.nuisance_gate_sessions import FILESYSTEM, KUBERNETES
from tests.unit.support.captured_console import a_captured_console
from tests.unit.support.nuisance_holdout_runs import COUNTED_TOOL

REPORT_PATH = Path("output/nuisance_gate_report.json")


def test_the_summary_states_the_commit_and_the_model(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)

    print_nuisance_gate_summary(given.a_red_report(), REPORT_PATH)

    assert "Commit: c0ffee" in output.getvalue()
    assert "Model: openai gpt-6-luna, judge gpt-6-luna, 3 run(s), concurrency 9" in (
        output.getvalue()
    )


def test_the_table_shows_each_server_with_its_baseline_runs_and_retests(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)

    print_nuisance_gate_summary(given.a_red_report(), REPORT_PATH)

    rows = [row.strip() for row in output.getvalue().splitlines()]
    [regression] = [row for row in rows if row.startswith(KUBERNETES.server_package)]
    assert regression.split()[1:5] == ["regression", "......", "A..", "4/5"]
    assert COUNTED_TOOL in regression
    assert any(row.startswith(FILESYSTEM.server_package) for row in rows)
    assert GATE_LEGEND in output.getvalue()


def test_an_inconclusive_server_shows_its_detail_before_its_flagged_tools(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)

    print_nuisance_gate_summary(given.an_inconclusive_report(), REPORT_PATH)

    assert f"{FLAGGED_IN_BASELINE}; run 1: {COUNTED_TOOL}" in output.getvalue()


def test_the_summary_lists_the_servers_not_admitted_and_outside_the_gate(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)

    print_nuisance_gate_summary(given.a_red_report(), REPORT_PATH)

    assert NOT_ADMITTED in output.getvalue()
    outside = f"{OUTSIDE.server_package}: {EXIT_REASON_TEXTS[OUTSIDE.reason]}"
    assert outside in output.getvalue()


def test_a_not_run_reason_holding_markup_prints_literally(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)
    report = given.a_report_with_a_server_not_run("benign call failed: [bold]boom[/bold]")

    print_nuisance_gate_summary(report, REPORT_PATH)

    assert f"{KUBERNETES.server_package}: benign call failed: [bold]boom[/bold]" in (
        output.getvalue()
    )


def test_the_summary_states_the_throttled_requests_only_when_there_were_some(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)

    print_nuisance_gate_summary(given.a_red_report(throttled_requests=12), REPORT_PATH)
    throttled = output.getvalue()
    output = a_captured_console(capsys, monkeypatch)
    print_nuisance_gate_summary(given.a_red_report(), REPORT_PATH)

    assert "Throttled by the model provider: 12 requests at concurrency 9" in throttled
    assert "Throttled" not in output.getvalue()


def test_the_report_paths_name_the_judged_cases_export(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)

    print_nuisance_gate_summary(given.a_red_report(), REPORT_PATH)

    assert (
        "Report written to output/nuisance_gate_report.json and output/nuisance_gate_report.md,"
        " judged cases exported to output/nuisance_gate_judged_cases.jsonl"
    ) in output.getvalue()


def test_the_summary_ends_with_the_verdict_panel(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)
    report = given.a_red_report()
    print_nuisance_gate_summary(report, REPORT_PATH)
    summary = output.getvalue()
    output = a_captured_console(capsys, monkeypatch)

    print_outcome(report.gate.outcome, report.gate.reasons)

    assert summary.endswith(output.getvalue())
    assert summary.count("Gate red.") == 1


def test_the_summary_leaves_the_recording_and_the_orphans_out(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)

    print_nuisance_gate_summary(given.a_report_that_recorded(), REPORT_PATH)

    assert "recorded" not in output.getvalue()
    assert "npm-gone.json" not in output.getvalue()
    assert "the tree changed during the runs" not in output.getvalue()
