"""The nuisance gate's console summary, from the report alone: the `.md` keeps the full record,
and `nuisance_gate_command` prints the recording after it."""

from pathlib import Path

from rich.text import Text

from evals.cell_grid import replay_fraction
from evals.eval_display import GateRow, console, gate_table, print_report_paths, print_verdict
from evals.export import nuisance_gate_export_path
from evals.nuisance_gate_report import (
    GATE_LEGEND,
    NuisanceGateReport,
    render_conditions,
    render_throttled,
    server_detail,
    server_letters,
)


def print_nuisance_gate_summary(report: NuisanceGateReport, report_path: Path) -> None:
    _print_lines(render_conditions(report))
    console.print(gate_table(_gate_rows(report), "Server"))
    _print_lines([GATE_LEGEND])
    _print_listed("Not run:", [f"{p}: {why}" for p, why in report.not_run.items()])
    _print_listed("Not admitted:", report.not_admitted)
    _print_listed(
        "Outside the gate:", [f"{e.server_package}: {e.reason}" for e in report.outside_gate]
    )
    for line in render_throttled(report):
        console.print(Text(line, style="yellow"))
    print_report_paths(report_path, nuisance_gate_export_path(report_path))
    print_verdict(report.gate.verdict, report.gate.reasons)


def _print_lines(lines: list[str]) -> None:
    for line in lines:
        console.print(Text(line))


def _print_listed(title: str, items: list[str]) -> None:
    if items:
        _print_lines([title, *(f"- {item}" for item in items)])


def _gate_rows(report: NuisanceGateReport) -> list[GateRow]:
    lines = {line.server_package: line for line in report.servers}
    return [
        GateRow(
            target=comparison.server_package,
            outcome=comparison.outcome.value,
            baseline=server_letters(comparison.baseline_runs) or "-",
            run=server_letters(comparison.candidate_runs) or "-",
            replays=replay_fraction(comparison.replays),
            detail=server_detail(comparison, lines.get(comparison.server_package)),
        )
        for comparison in report.gate.servers
    ]
