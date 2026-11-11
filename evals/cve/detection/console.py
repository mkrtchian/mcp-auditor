"""The detection suite's console summary, from the report alone: the `.md` keeps the full record."""

from pathlib import Path

from rich.table import Table
from rich.text import Text

from evals.cell_grid import retest_fraction
from evals.cve.detection.costs import (
    COST_COLUMNS,
    TIERED_REQUEST_INPUT_TOKENS,
    cost_cells,
    large_request_targets,
)
from evals.cve.detection.gate import DetectionGateResult
from evals.cve.detection.markdown import (
    GATE_LEGEND,
    render_conditions,
    render_cost_title,
    render_measurement_lines,
    render_not_run,
    render_replay_credits,
    render_tally,
    run_fraction,
    status_letters,
)
from evals.cve.detection.oracle import DetectionReport, TargetResult
from evals.eval_display import GateRow, console, gate_table, print_outcome, print_report_paths
from evals.export import detection_export_path
from evals.gate_outcome import GateOutcome


def print_detection_summary(report: DetectionReport, report_path: Path) -> None:
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
    print_report_paths(report_path, detection_export_path(report_path))
    _print_outcome(report.gate)


def _print_outcome(gate: DetectionGateResult | None) -> None:
    if gate is None:
        console.print(
            "[yellow]No-baseline run: nothing compared to evals/baselines/detection/.[/yellow]"
        )
    else:
        print_outcome(GateOutcome(gate.outcome.value), gate.reasons)


def _print_lines(lines: list[str]) -> None:
    for line in lines:
        console.print(Text(line))


def _results_table(results: list[TargetResult]) -> Table:
    table = Table(box=None, header_style="bold")
    table.add_column("Flaw", no_wrap=True)
    for column in ("Status", "Detected", "Miss class", "Aimed", "FAIL without proof"):
        table.add_column(column)
    for result in results:
        cells = (
            result.flaw_id,
            result.status.value,
            run_fraction(result.detected_runs, result.runs),
            result.miss_class or "-",
            run_fraction(result.aimed_runs, result.runs),
            run_fraction(result.fail_without_proof_runs, result.runs),
        )
        table.add_row(*(Text(cell) for cell in cells))
    return table


def _print_costs(report: DetectionReport) -> None:
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
    for flaw_id in large_request_targets(report.costs):
        console.print(
            Text(
                f"{flaw_id}: a request above {TIERED_REQUEST_INPUT_TOKENS} input tokens, its cost "
                "is under-reported for a vendor that bills such a request higher.",
                style="yellow",
            )
        )


def _gate_rows(gate: DetectionGateResult) -> list[GateRow]:
    return [
        GateRow(
            subject=comparison.flaw_id,
            outcome=comparison.outcome.value,
            baseline=status_letters(comparison.baseline_runs) or "-",
            run=status_letters(comparison.candidate_runs) or "-",
            retests=retest_fraction(comparison.retests),
            detail=comparison.detail or "-",
        )
        for comparison in gate.targets
    ]
