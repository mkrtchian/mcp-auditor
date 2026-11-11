from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

import tests.unit.support.test_eval_display_given as given
from evals.cell_grid import CellTag
from evals.eval_display import (
    GateRow,
    gate_table,
    print_outcome,
    print_recorded_grid,
    print_report_paths,
    print_summary,
)
from evals.gate_outcome import GateOutcome


def test_the_summary_states_the_throttled_requests_and_the_concurrency(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.a_captured_console(monkeypatch)
    report = given.an_eval_report({"concurrency": 6, "throttled_requests": 4})

    print_summary(report, "output/honeypot_report.json")

    assert "Throttled by the model provider: 4 requests at concurrency 6" in output.getvalue()


@pytest.mark.parametrize(
    "config", [{"concurrency": 6, "throttled_requests": 0}, {"concurrency": 6}]
)
def test_the_summary_says_nothing_of_throttling_when_nothing_was_throttled(
    monkeypatch: pytest.MonkeyPatch, config: dict[str, int]
):
    output = given.a_captured_console(monkeypatch)

    print_summary(given.an_eval_report(config), "output/honeypot_report.json")

    assert "Throttled" not in output.getvalue()


def test_the_summary_names_a_declared_cell_that_did_not_flip(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_summary(given.an_eval_report(declared_held=["query/injection"]), "report.json")

    assert "declared, did not flip: query/injection" in output.getvalue()


def test_the_summary_notes_the_declarations_ignored_on_a_dirty_tree(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.a_captured_console(monkeypatch)

    print_summary(
        given.an_eval_report(),
        "report.json",
        ignored_declarations=frozenset({"query/injection"}),
    )

    assert (
        "Declarations of HEAD ignored, the tree has tracked changes: query/injection"
        in output.getvalue()
    )


def test_the_summary_says_nothing_of_declarations_when_there_are_none(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.a_captured_console(monkeypatch)

    print_summary(given.an_eval_report(), "report.json")

    assert "declar" not in output.getvalue()


def test_the_summary_explains_a_partial_row(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)
    grid = given.a_gate_grid_with_an_outcome_row("partial")

    print_summary(given.an_eval_report(), "report.json", grid)

    assert (
        "partial: wrong in every baseline run, right in some runs of this one, not gated"
        in output.getvalue()
    )


def test_the_summary_says_nothing_of_partial_rows_when_there_are_none(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.a_captured_console(monkeypatch)
    grid = given.a_gate_grid_with_an_outcome_row("regression")

    print_summary(given.an_eval_report(), "report.json", grid)

    assert "partial:" not in output.getvalue()


def test_the_summary_ends_with_the_verdict_panel(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)
    print_summary(given.an_eval_report(), "report.json")
    summary = output.getvalue()
    output.truncate(0)
    output.seek(0)

    print_outcome(GateOutcome.GREEN, [])

    assert summary.endswith(output.getvalue())


def test_the_verdict_panel_states_the_verdict_and_its_reasons_literally(
    monkeypatch: pytest.MonkeyPatch,
):
    output = given.a_captured_console(monkeypatch)

    print_outcome(GateOutcome.RED, ["regression on [bold]query[/bold]"])

    assert "Gate red." in output.getvalue()
    assert "- regression on [bold]query[/bold]" in output.getvalue()


def test_the_gate_table_keeps_a_long_subject_id_whole():
    subject = "very-long-server-package-name-that-would-wrap"
    row = GateRow(subject, "not_gated", "MMM", "MDM", "1/2", "a long detail " * 8)
    buffer = StringIO()

    Console(file=buffer, width=80).print(gate_table([row], "Server"))

    assert subject in buffer.getvalue()


def test_the_gate_table_prints_a_markup_cell_literally():
    row = GateRow("CVE-X", "held", "DDD", "DDD", "-", "[bold]x[/bold]")
    buffer = StringIO()

    Console(file=buffer, width=200).print(gate_table([row], "CVE"))

    assert "[bold]x[/bold]" in buffer.getvalue()


def test_the_report_paths_name_the_json_and_the_markdown(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_report_paths(Path("output/cve.json"))

    assert "Report written to output/cve.json and output/cve.md" in output.getvalue()
    assert "exported" not in output.getvalue()


def test_the_report_paths_name_the_export_when_given(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_report_paths(Path("output/cve.json"), Path("output/detection_judged_cases.jsonl"))

    assert (
        "Report written to output/cve.json and output/cve.md,"
        " judged cases exported to output/detection_judged_cases.jsonl"
    ) in output.getvalue()


def test_the_grid_tags_a_false_positive_and_an_improved_cell(monkeypatch: pytest.MonkeyPatch):
    output = given.a_captured_console(monkeypatch)

    print_recorded_grid("Baseline", given.a_grid_tagging(CellTag.FALSE_POSITIVE, CellTag.IMPROVED))

    printed = output.getvalue()
    assert " false_positive " in printed and " improved " in printed
    assert "false positive: PASS cell judged FAIL in every baseline run" in printed
    assert "miss or false-positive cell correct in every run of this one" in printed
