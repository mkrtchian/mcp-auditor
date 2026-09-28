from pathlib import Path

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table
from rich.text import Text

from evals.baseline import Baseline, BaselineStatus
from evals.cell_grid import CellTag, GateGrid, GridBox, GridSection, OutcomeRow
from evals.eval_report import EvalReport
from evals.gate import ProtectedCells
from evals.gate_verdict import GateMode, GateResult, GateVerdict
from evals.metrics import RunDetail
from evals.recording import GatedSetChange
from mcp_auditor.domain.models import AuditCategory

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


def print_summary(report: EvalReport, report_path: str, grid: GateGrid | None = None) -> None:
    gate = report.gate
    status = f", baseline {gate.baseline_status}" if gate.baseline_status else ""
    console.print(f"Gate mode: [bold]{gate.mode}[/bold]{status}")
    console.print(Panel(_metrics_table(report), title="Eval Results"))
    if grid and grid.sections:
        _print_grid(grid.title, grid.sections, gated_run=True)
    if grid and grid.outcomes:
        console.print(_outcome_table(grid.outcomes))
        console.print("P pass, F fail, - not covered")
    if gate.protected:
        console.print(f"Baseline under the current labels: {_protected_line(gate.protected)}")
    throttled = report.config.get("throttled_requests", 0)
    if throttled > 0:
        console.print(
            f"[yellow]Throttled by the model provider: {throttled} requests"
            f" at concurrency {report.config['concurrency']}[/yellow]"
        )
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
        value: float = getattr(report.metrics, name)
        limit = limits.get(name)
        if limit is None:
            table.add_row(label, f"{value:.2f}", "-", "")
            continue
        # A floor's status reads from the gate: recall's floor is a count, which a rounded mean
        # compared with 1/planted could contradict.
        passed = value >= limit if legacy else name not in report.gate.floor_breaches
        table.add_row(label, f"{value:.2f}", f"{limit:.2f}", _status(passed))
    return table


def _status(passed: bool) -> str:
    return "[green]PASS[/green]" if passed else "[red]FAIL[/red]"


def print_recorded_grid(title: str, sections: list[GridSection]) -> None:
    _print_grid(title, sections, gated_run=False)


_STYLES: dict[CellTag, str] = {
    CellTag.GATE: "black on green",
    CellTag.UNSTABLE: "black on yellow",
    CellTag.MISS: "white on magenta",
    CellTag.ALARM: "white on magenta",
    CellTag.FLIP: "black on bright_yellow",
    CellTag.REGRESSION: "bold white on bright_red",
    CellTag.FIXED: "black on cyan",
    CellTag.NEW: "black on white",
}

_MEANINGS: dict[CellTag, str] = {
    CellTag.GATE: "gated: same correct verdict in every baseline run",
    CellTag.UNSTABLE: "not gated: verdict varies across baseline runs",
    CellTag.MISS: "not gated: planted flaw never found",
    CellTag.ALARM: "not gated: PASS cell always flagged",
    CellTag.FLIP: "gated cell wrong in this run, not a regression",
    CellTag.REGRESSION: "gated cell wrong in this run, reproduced on replay: the gate fails",
    CellTag.FIXED: "miss or alarm cell correct in every run of this one",
    CellTag.NEW: "cell the baseline did not record",
}

_SHORT_CATEGORY: dict[AuditCategory, str] = {
    AuditCategory.INPUT_VALIDATION: "input",
    AuditCategory.ERROR_HANDLING: "errors",
    AuditCategory.INJECTION: "inject",
    AuditCategory.INFO_LEAKAGE: "leak",
    AuditCategory.RESOURCE_ABUSE: "abuse",
}


def _print_grid(title: str, sections: list[GridSection], gated_run: bool) -> None:
    console.print(title)
    console.print(_grid_table(sections))
    console.print(_legend(sections, gated_run))


def _grid_table(sections: list[GridSection]) -> Table:
    table = Table(box=box.ROUNDED)
    table.add_column("tool", max_width=20, overflow="ellipsis")
    for category in AuditCategory:
        header = _SHORT_CATEGORY.get(category, category.value[:7])
        table.add_column(header, justify="center", min_width=7)
    empty = [""] * len(AuditCategory)
    for section in sections:
        table.add_row(Text(section.honeypot, style="dim italic"), *empty)
        for index, row in enumerate(section.rows):
            boxes = [_box_text(row.boxes[category]) for category in AuditCategory]
            table.add_row(row.tool, *boxes, end_section=index == len(section.rows) - 1)
    return table


def _box_text(grid_box: GridBox | None) -> Text:
    if grid_box is None:
        return Text("·", style="dim")
    star = "*" if grid_box.planted else " "
    # Centring would strip the trailing space and shift unstarred words right of starred ones.
    return Text(f" {grid_box.tag}{star}", style=_STYLES[grid_box.tag], justify="left")


def _legend(sections: list[GridSection], gated_run: bool) -> Table:
    boxes = [
        grid_box for section in sections for row in section.rows for grid_box in row.boxes.values()
    ]
    present = [grid_box for grid_box in boxes if grid_box is not None]
    legend = Table.grid(padding=(0, 2))
    for tag in CellTag:
        if any(grid_box.tag == tag for grid_box in present):
            legend.add_row(Text(f" {tag} ", style=_STYLES[tag]), Text(_MEANINGS[tag], style="dim"))
    if any(grid_box.planted for grid_box in present):
        legend.add_row(" *", Text("planted flaw", style="dim"))
    if len(present) < len(boxes):
        legend.add_row(Text(" ·", style="dim"), Text("no such cell", style="dim"))
    if gated_run:
        legend.add_row(
            "",
            Text(
                "a box counts the runs of the baseline, the outcome table the runs of this one",
                style="dim",
            ),
        )
    return legend


def _outcome_table(rows: list[OutcomeRow]) -> Table:
    table = Table(box=None, header_style="bold")
    for column in ("Outcome", "Cell", "Baseline", "Run", "Replays"):
        table.add_column(column, overflow="fold")
    for row in rows:
        cell = f"{row.cell}*" if row.planted else row.cell
        table.add_row(row.outcome, cell, row.baseline, row.run, row.replays)
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
    for refused in run_detail.refused_steps:
        progress.console.print(f"  Refused by the model provider, {escape(refused)}")


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
    if baseline.confirms is not None or baseline.replaces is not None:
        lines += [f"- enters the gated set: {key}" for key in gated_changes.entering]
        lines += [f"- leaves the gated set: {key}" for key in gated_changes.leaving]
    lines += [
        f"- looked stable in the first recording and varied in the second: {key}"
        for key in baseline.disagreements
    ]
    if baseline.protected:
        lines.append(_protected_line(baseline.protected))
    lines.append(_NEXT_STEP[baseline.status])
    console.print(Panel("\n".join(lines)))


def _protected_line(protected: ProtectedCells) -> str:
    return (
        f"planted FAIL cells stable and correct: "
        f"{protected.fail_stable_correct}/{protected.fail_total}, "
        f"PASS cells stable and correct: {protected.pass_stable_correct}/{protected.pass_total}, "
        f"unstable: {protected.unstable}"
    )
