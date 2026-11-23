from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from evals.eval_display import GateRow, gate_table, print_outcome, print_report_paths
from evals.gate_outcome import GateOutcome
from tests.unit.support.captured_console import a_captured_console


def test_the_verdict_panel_states_the_verdict_and_its_reasons_literally(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    output = a_captured_console(capsys, monkeypatch)

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


def test_the_report_paths_name_the_json_and_the_markdown(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)

    print_report_paths(Path("output/cve.json"))

    assert "Report written to output/cve.json and output/cve.md" in output.getvalue()
    assert "exported" not in output.getvalue()


def test_the_report_paths_name_the_export_when_given(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    output = a_captured_console(capsys, monkeypatch)

    print_report_paths(Path("output/cve.json"), Path("output/detection_judged_cases.jsonl"))

    assert (
        "Report written to output/cve.json and output/cve.md,"
        " judged cases exported to output/detection_judged_cases.jsonl"
    ) in output.getvalue()
