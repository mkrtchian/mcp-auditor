from pathlib import Path

import pytest

import tests.unit.support.test_nuisance_gate_console_given as given
from evals.eval_display import print_verdict
from evals.nuisance_gate_console import print_nuisance_gate_summary
from evals.nuisance_gate_report import GATE_LEGEND
from tests.unit.support.test_nuisance_gate_report_given import (
    FLAGGED_IN_BASELINE,
    NOT_ADMITTED,
    OUTSIDE,
)
from tests.unit.support.test_nuisance_gate_session_given import FILESYSTEM, KUBERNETES
from tests.unit.support.test_nuisance_run_given import COUNTED_TOOL

REPORT_PATH = Path("output/nuisance_gate_report.json")


def test_the_summary_states_the_commit_and_the_model(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_nuisance_gate_summary(given.a_red_report(), REPORT_PATH)

    assert "Commit: c0ffee" in output.getvalue()
    assert "Model: openai gpt-6-luna, judge gpt-6-luna, 3 run(s), concurrency 9" in (
        output.getvalue()
    )


def test_the_table_shows_each_server_with_its_baseline_runs_and_replays(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.a_captured_console(monkeypatch)

    print_nuisance_gate_summary(given.a_red_report(), REPORT_PATH)

    rows = [row.strip() for row in output.getvalue().splitlines()]
    [regression] = [row for row in rows if row.startswith(KUBERNETES.server_package)]
    assert regression.split()[1:5] == ["regression", "......", "A..", "4/5"]
    assert COUNTED_TOOL in regression
    assert any(row.startswith(FILESYSTEM.server_package) for row in rows)
    assert GATE_LEGEND in output.getvalue()


def test_the_detail_reads_as_in_the_markdown(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_nuisance_gate_summary(given.a_not_gated_report(), REPORT_PATH)

    assert f"{FLAGGED_IN_BASELINE}; run 1: {COUNTED_TOOL}" in output.getvalue()


def test_the_summary_lists_the_servers_not_admitted_and_outside_the_gate(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.a_captured_console(monkeypatch)

    print_nuisance_gate_summary(given.a_red_report(), REPORT_PATH)

    assert NOT_ADMITTED in output.getvalue()
    assert f"{OUTSIDE.server_package}: {OUTSIDE.reason}" in output.getvalue()


def test_a_not_run_reason_holding_markup_prints_literally(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)
    report = given.a_report_with_a_server_not_run("benign call failed: [bold]boom[/bold]")

    print_nuisance_gate_summary(report, REPORT_PATH)

    assert f"{KUBERNETES.server_package}: benign call failed: [bold]boom[/bold]" in (
        output.getvalue()
    )


def test_the_summary_states_the_throttled_requests_only_when_there_were_some(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.a_captured_console(monkeypatch)

    print_nuisance_gate_summary(given.a_red_report(throttled_requests=12), REPORT_PATH)
    throttled = output.getvalue()
    output.truncate(0)
    output.seek(0)
    print_nuisance_gate_summary(given.a_red_report(), REPORT_PATH)

    assert "Throttled by the model provider: 12 requests at concurrency 9" in throttled
    assert "Throttled" not in output.getvalue()


def test_the_report_paths_name_the_judged_cases_export(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_nuisance_gate_summary(given.a_red_report(), REPORT_PATH)

    assert (
        "Report written to output/nuisance_gate_report.json and output/nuisance_gate_report.md,"
        " judged cases exported to output/nuisance_gate_judged_cases.jsonl"
    ) in output.getvalue()


def test_the_summary_ends_with_the_verdict_panel(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)
    report = given.a_red_report()
    print_nuisance_gate_summary(report, REPORT_PATH)
    summary = output.getvalue()
    output.truncate(0)
    output.seek(0)

    print_verdict(report.gate.verdict, report.gate.reasons)

    assert summary.endswith(output.getvalue())
    assert summary.count("Gate red.") == 1


def test_the_summary_leaves_the_recording_and_the_orphans_out(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_nuisance_gate_summary(given.a_report_that_recorded(), REPORT_PATH)

    assert "recorded" not in output.getvalue()
    assert "npm-gone.json" not in output.getvalue()
    assert "the tree changed during the runs" not in output.getvalue()
