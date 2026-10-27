from pathlib import Path

import pytest

import tests.unit.support.test_cve_console_given as given
from evals.cve_console import print_cve_summary
from evals.eval_display import print_verdict
from evals.gate_verdict import GateVerdict

REPORT_PATH = Path("output/cve_report.json")


def test_the_summary_shows_each_target_id_whole(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_cve_summary(given.a_gated_report(), REPORT_PATH)

    for cve_id in (given.DETECTED_CVE, "CVE-2025-53355"):
        assert cve_id in output.getvalue()


def test_the_summary_states_the_tally(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_cve_summary(given.a_gated_report(), REPORT_PATH)

    assert "Statuses: 1 detected." in output.getvalue()


def test_the_summary_states_the_throttled_requests_and_the_concurrency(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.a_captured_console(monkeypatch)

    print_cve_summary(given.a_gated_report(throttled_requests=7), REPORT_PATH)

    assert "Throttled by the model provider: 7 requests at concurrency 4" in output.getvalue()


def test_the_summary_says_nothing_of_throttling_when_nothing_was_throttled(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.a_captured_console(monkeypatch)

    print_cve_summary(given.a_gated_report(), REPORT_PATH)

    assert "Throttled" not in output.getvalue()


def test_the_report_paths_name_the_judged_cases_export(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_cve_summary(given.a_gated_report(), REPORT_PATH)

    assert (
        "Report written to output/cve_report.json and output/cve_report.md,"
        " judged cases exported to output/cve_judged_cases.jsonl"
    ) in output.getvalue()


def test_the_summary_ends_with_the_verdict_panel(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)
    report = given.a_gated_report()
    print_cve_summary(report, REPORT_PATH)
    summary = output.getvalue()
    output.truncate(0)
    output.seek(0)

    assert report.gate is not None
    print_verdict(GateVerdict.RED, report.gate.reasons)

    assert summary.endswith(output.getvalue())


def test_an_ungated_summary_says_so_and_prints_no_verdict_panel(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_cve_summary(given.an_ungated_report(), REPORT_PATH)

    assert "Ungated run: nothing compared to evals/baselines/cve/." in output.getvalue()
    assert "Gate " not in output.getvalue()
    assert "Not comparable." not in output.getvalue()


def test_the_summary_never_prints_a_gate_line(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_cve_summary(given.a_gated_report(), REPORT_PATH)

    assert "Gate:" not in output.getvalue()


def test_the_commit_line_marks_a_dirty_tree(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_cve_summary(given.a_gated_report(dirty=True), REPORT_PATH)

    assert "Commit: c0ffee (dirty tree)" in output.getvalue()


def test_the_commit_line_of_a_clean_tree_carries_no_mark(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_cve_summary(given.a_gated_report(), REPORT_PATH)

    assert "Commit: c0ffee" in output.getvalue()
    assert "dirty" not in output.getvalue()


def test_an_ungated_summary_lists_the_targets_not_run(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)
    report = given.a_report_with_a_not_run_target(["exploit dead"], gated=False)

    print_cve_summary(report, REPORT_PATH)

    assert "Not run, pre-run check failed:" in output.getvalue()
    assert f"- {given.NOT_RUN_CVE}: exploit dead" in output.getvalue()


def test_a_gated_summary_leaves_the_targets_not_run_to_the_gate(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)
    report = given.a_report_with_a_not_run_target(["exploit dead"], gated=True)

    print_cve_summary(report, REPORT_PATH)

    assert "Not run, pre-run check failed:" not in output.getvalue()


def test_the_cost_title_carries_the_price_date(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_cve_summary(given.a_priced_ungated_report(), REPORT_PATH)

    assert (
        "Cost per target, all attempts, dollars at the prices as of 2026-10-01:"
        in output.getvalue()
    )
    assert "$0.7500" in output.getvalue()


def test_a_not_run_condition_holding_markup_prints_literally(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)
    report = given.a_report_with_a_not_run_target(["[bold]dead[/bold]"], gated=False)

    print_cve_summary(report, REPORT_PATH)

    assert "[bold]dead[/bold]" in output.getvalue()


def test_a_gate_detail_holding_markup_prints_literally(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_cve_summary(given.a_report_gated_on_a_detail("[bold]dead[/bold]"), REPORT_PATH)

    assert "[bold]dead[/bold]" in output.getvalue()
