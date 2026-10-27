"""The CVE benchmark's console summary, from the report alone: the `.md` keeps the full record."""

from pathlib import Path

from rich.table import Table
from rich.text import Text

from evals.cell_grid import replay_fraction
from evals.cve_costs import (
    COST_COLUMNS,
    TIERED_REQUEST_INPUT_TOKENS,
    cost_cells,
    large_request_targets,
)
from evals.cve_gate import CVEGateResult
from evals.cve_oracle import (
    GATE_LEGEND,
    CVEBenchmarkReport,
    CVEResult,
    render_conditions,
    render_cost_title,
    render_measurement_lines,
    render_not_run,
    render_replay_credits,
    render_tally,
    run_fraction,
    status_letters,
)
from evals.eval_display import GateRow, console, gate_table, print_report_paths, print_verdict
from evals.export import cve_export_path
from evals.gate_verdict import GateVerdict


def print_cve_summary(report: CVEBenchmarkReport, report_path: Path) -> None:
    dirty = " (dirty tree)" if report.dirty else ""
    header = [f"Commit: {report.commit}{dirty}", render_conditions(report)]
    _print_lines([*header, *render_measurement_lines(report)])
    console.print(_results_table(report.results))
    _print_lines([render_tally(report.results)])
    if report.gate is None:
        _print_lines(render_not_run(report.results))
    _print_lines(render_replay_credits(report.results))
    if report.gate is None:
        _print_costs(report)
    if report.throttled_requests > 0:
        console.print(
            f"[yellow]Throttled by the model provider: {report.throttled_requests} requests"
            f" at concurrency {report.concurrency}[/yellow]"
        )
    if report.gate is not None:
        console.print(gate_table(_gate_rows(report.gate), "Target"))
        _print_lines([GATE_LEGEND])
    print_report_paths(report_path, cve_export_path(report_path))
    _print_verdict(report.gate)


def _print_verdict(gate: CVEGateResult | None) -> None:
    if gate is None:
        console.print("[yellow]Ungated run: nothing compared to evals/baselines/cve/.[/yellow]")
    else:
        print_verdict(GateVerdict(gate.verdict.value), gate.reasons)


def _print_lines(lines: list[str]) -> None:
    for line in lines:
        console.print(Text(line))


def _results_table(results: list[CVEResult]) -> Table:
    table = Table(box=None, header_style="bold")
    table.add_column("CVE", no_wrap=True)
    for column in ("Status", "Detected", "Miss class", "Aimed", "FAIL without proof"):
        table.add_column(column)
    for result in results:
        cells = (
            result.cve_id,
            result.status.value,
            run_fraction(result.detected_runs, result.runs),
            result.miss_class or "-",
            run_fraction(result.aimed_runs, result.runs),
            run_fraction(result.fail_without_proof_runs, result.runs),
        )
        table.add_row(*(Text(cell) for cell in cells))
    return table


def _print_costs(report: CVEBenchmarkReport) -> None:
    if not report.costs:
        return
    _print_lines([render_cost_title(report)])
    table = Table(box=None, header_style="bold")
    table.add_column(COST_COLUMNS[0], no_wrap=True)
    for column in COST_COLUMNS[1:]:
        table.add_column(column, justify="right")
    for cost in report.costs:
        table.add_row(*(Text(cell) for cell in cost_cells(cost)))
    console.print(table)
    for cve_id in large_request_targets(report.costs):
        console.print(
            Text(
                f"{cve_id}: a request above {TIERED_REQUEST_INPUT_TOKENS} input tokens, its cost "
                "is under-reported for a vendor that bills such a request higher.",
                style="yellow",
            )
        )


def _gate_rows(gate: CVEGateResult) -> list[GateRow]:
    return [
        GateRow(
            target=comparison.cve_id,
            outcome=comparison.outcome.value,
            baseline=status_letters(comparison.baseline_runs) or "-",
            run=status_letters(comparison.candidate_runs) or "-",
            replays=replay_fraction(comparison.replays),
            detail=comparison.detail or "-",
        )
        for comparison in gate.targets
    ]
