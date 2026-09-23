from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table

from evals.baseline import Baseline, BaselineStatus
from evals.eval_report import EvalReport
from evals.gate import CellComparison, CellOutcome
from evals.gate_verdict import GateMode, GateResult, GateVerdict
from evals.metrics import RunDetail
from evals.recording import GatedSetChange

console = Console()

_METRIC_LABELS = {
    "recall": "Recall",
    "precision": "Precision",
    "consistency": "Consistency",
    "distribution_coverage": "Distribution",
}

_VERDICT_STYLES = {
    GateVerdict.GREEN: "[bold green]Gate green.[/bold green]",
    GateVerdict.RED: "[bold red]Gate red.[/bold red]",
    GateVerdict.NOT_COMPARABLE: "[bold red]Not comparable.[/bold red]",
}


def print_summary(report: EvalReport, report_path: str) -> None:
    gate = report.gate
    status = f", baseline {gate.baseline_status}" if gate.baseline_status else ""
    console.print(f"Gate mode: [bold]{gate.mode}[/bold]{status}")
    console.print(Panel(_metrics_table(report), title="Eval Results"))
    changed = {
        key: cell for key, cell in gate.cells.items() if cell.outcome != CellOutcome.UNCHANGED
    }
    if changed:
        console.print(Panel(_cells_table(changed), title="Cells"))
    console.print(f"Report written to {report_path}")
    console.print(Panel(_verdict_text(gate)))


def _metrics_table(report: EvalReport) -> Table:
    legacy = report.gate.mode == GateMode.LEGACY_THRESHOLDS
    limits = report.thresholds if legacy else report.gate.floors
    table = Table(show_header=True, header_style="bold")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_column("Threshold" if legacy else "Floor", justify="right")
    table.add_column("Status")
    for name, label in _METRIC_LABELS.items():
        _add_metric_row(table, label, getattr(report.metrics, name), limits.get(name))
    return table


def _add_metric_row(table: Table, name: str, value: float, limit: float | None) -> None:
    if limit is None:
        table.add_row(name, f"{value:.2f}", "-", "")
        return
    status = "[green]PASS[/green]" if value >= limit else "[red]FAIL[/red]"
    table.add_row(name, f"{value:.2f}", f"{limit:.2f}", status)


def _cells_table(cells: dict[str, CellComparison]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("Cell")
    table.add_column("Outcome")
    table.add_column("Cause")
    table.add_column("Replays reproduced", justify="right")
    for key, cell in sorted(cells.items()):
        replays = f"{sum(cell.replays)}/{len(cell.replays)}" if cell.replays else "-"
        table.add_row(key, cell.outcome, cell.cause or "-", replays)
    return table


def _verdict_text(gate: GateResult) -> str:
    lines = [_VERDICT_STYLES[gate.verdict], *_bullets(gate.reasons)]
    return "\n".join(lines)


def _bullets(reasons: list[str]) -> list[str]:
    return [f"- {escape(reason)}" for reason in reasons]


def print_run_result(run_detail: RunDetail, progress: Progress) -> None:
    for tool_name, dist in run_detail.distribution.items():
        total_cases = sum(v.case_count for v in run_detail.verdicts.get(tool_name, {}).values())
        progress.console.print(
            f"  [bold]{tool_name}[/bold]: {total_cases} cases, {dist.covered} categories covered"
        )
    progress.console.print(
        f"  Recall: {run_detail.recall:.2f} | Precision: {run_detail.precision:.2f}"
    )
    for reason in run_detail.blocked_reasons:
        progress.console.print(f"  Payload blocked, {reason}")


def print_refusal(title: str, reasons: list[str]) -> None:
    lines = [f"[bold red]{title}[/bold red]", *_bullets(reasons)]
    console.print(Panel("\n".join(lines)))


_NEXT_STEP = {
    BaselineStatus.EXPLORATORY: (
        "Run --record-baseline again now, at this commit and before committing, to confirm it. "
        "Commit the file once confirmed."
    ),
    BaselineStatus.CONFIRMED: "Commit the file by hand.",
}


def print_written_recording(baseline: Baseline, gated_changes: GatedSetChange, path: Path) -> None:
    lines = [f"[bold green]Baseline recorded ({baseline.status}) to {path}.[/bold green]"]
    lines += [f"- enters the gated set: {key}" for key in gated_changes.entering]
    lines += [f"- leaves the gated set: {key}" for key in gated_changes.leaving]
    lines += [
        f"- disagrees with the recording it replaces: {key}" for key in baseline.disagreements
    ]
    lines.append(_NEXT_STEP[baseline.status])
    console.print(Panel("\n".join(lines)))
