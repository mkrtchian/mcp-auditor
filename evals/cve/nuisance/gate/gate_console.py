"""The nuisance gate's console summary, from the report alone: the `.md` keeps the full record,
and `gate_command` prints the recording after it."""

from pathlib import Path

from rich.text import Text

from evals.cve.nuisance.gate.gate_judged_cases_export import nuisance_gate_export_path
from evals.cve.nuisance.gate.gate_report import (
    GATE_LEGEND,
    REPORT_ONLY,
    NuisanceGateReport,
    gate_rows,
    outside_gate_line,
    render_conditions,
)
from evals.eval_display import (
    console,
    gate_table,
    print_outcome,
    print_report_paths,
    print_throttles,
)


def print_nuisance_gate_summary(report: NuisanceGateReport, report_path: Path) -> None:
    _print_lines(render_conditions(report))
    console.print(gate_table(gate_rows(report), "Server"))
    _print_lines([GATE_LEGEND])
    _print_listed("Not run:", [f"{p}: {why}" for p, why in report.not_run.items()])
    _print_listed("Not admitted:", report.not_admitted)
    _print_listed("Outside the gate:", [outside_gate_line(e) for e in report.outside_gate])
    print_throttles(report.throttled_requests, report.concurrency)
    print_report_paths(report_path, nuisance_gate_export_path(report_path))
    if report.gate is None:
        console.print(f"[yellow]{REPORT_ONLY}[/yellow]")
    else:
        print_outcome(report.gate.outcome, report.gate.reasons)


def _print_lines(lines: list[str]) -> None:
    for line in lines:
        console.print(Text(line))


def _print_listed(title: str, items: list[str]) -> None:
    if items:
        _print_lines([title, *(f"- {item}" for item in items)])
