from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from evals.baseline import BaselineStatus
from evals.gate_outcome import GateOutcome

console = Console()

PARTIAL_LEGEND = "partial: wrong in every baseline run, right in some runs of this one, not gated"

RECORDING_NEXT_STEP: dict[BaselineStatus, str] = {
    BaselineStatus.UNCONFIRMED: (
        "Run --record-baseline again now, at this commit and before committing, to confirm it. "
        "Commit the file once confirmed."
    ),
    BaselineStatus.CONFIRMED: "Commit the file by hand.",
}

_OUTCOME_STYLES = {
    GateOutcome.GREEN: "[bold green]Gate green.[/bold green]",
    GateOutcome.RED: "[bold red]Gate red.[/bold red]",
    GateOutcome.NOT_COMPARABLE: "[bold red]Not comparable.[/bold red]",
}


def print_outcome(outcome: GateOutcome, reasons: list[str]) -> None:
    console.print(Panel("\n".join([_OUTCOME_STYLES[outcome], *_bullets(reasons)])))


def print_refusal(title: str, reasons: list[str]) -> None:
    lines = [f"[bold red]{title}[/bold red]", *_bullets(reasons)]
    console.print(Panel("\n".join(lines)))


def _bullets(reasons: list[str]) -> list[str]:
    return [f"- {escape(reason)}" for reason in reasons]


@dataclass(frozen=True)
class GateRow:
    subject: str
    outcome: str
    baseline: str
    run: str
    retests: str
    detail: str


def gate_table(rows: Sequence[GateRow], subject_header: str) -> Table:
    table = Table(box=None, header_style="bold")
    table.add_column(subject_header, no_wrap=True)
    for column in ("Outcome", "Baseline", "Run", "Retests"):
        table.add_column(column)
    table.add_column("Detail", overflow="fold")
    for row in rows:
        cells = (row.subject, row.outcome, row.baseline, row.run, row.retests, row.detail)
        table.add_row(*(Text(cell) for cell in cells))
    return table


def print_report_paths(report_path: Path, export: Path | None = None) -> None:
    line = f"Report written to {report_path} and {report_path.with_suffix('.md')}"
    if export is not None:
        line += f", judged cases exported to {export}"
    console.print(Text(line))


def print_declarations(held: list[str], ignored: frozenset[str]) -> None:
    for key in held:
        console.print(f"declared, did not flip: {key}")
    if ignored:
        console.print(
            "[yellow]Declarations of HEAD ignored, the tree has tracked changes:"
            f" {escape(', '.join(sorted(ignored)))}[/yellow]"
        )


def print_throttles(requests: int, concurrency: int) -> None:
    if requests > 0:
        console.print(
            f"[yellow]Throttled by the model provider: {requests} requests"
            f" at concurrency {concurrency}[/yellow]"
        )
