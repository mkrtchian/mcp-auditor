from pathlib import Path
from typing import Any

from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from evals.baseline import BaselineStatus
from evals.cell_grid import PARTIAL
from evals.eval_display import console, print_refusal
from evals.gate import ProtectedCells
from evals.gate_verdict import GateVerdict
from evals.judge_baseline import JUDGE_BASELINE_PATH, JudgeBaseline
from evals.judge_outcomes import CaseOutcomes, JudgeOutcomeRow
from evals.judge_session import JudgeSessionResult

__all__ = ["console", "print_refusal", "print_summary"]

_VERDICT_STYLES = {
    GateVerdict.GREEN: "[bold green]Gate green.[/bold green]",
    GateVerdict.RED: "[bold red]Gate red.[/bold red]",
    GateVerdict.NOT_COMPARABLE: "[bold red]Not comparable.[/bold red]",
}

_NEXT_STEP = {
    BaselineStatus.EXPLORATORY: (
        "Run --record-baseline again now, at this commit and before committing, to confirm it. "
        "Commit the file once confirmed."
    ),
    BaselineStatus.CONFIRMED: "Commit the file by hand.",
}


def print_summary(
    result: JudgeSessionResult, report: dict[str, Any], report_path: Path, outcomes: CaseOutcomes
) -> None:
    gate = result.gate
    status = f", baseline {gate.baseline_status}" if gate.baseline_status else ""
    console.print(f"Gate mode: [bold]{gate.mode}[/bold]{status}")
    console.print(Panel(_runs_table(report["per_run"]), title="Judge Eval Diagnostics"))
    console.print(_category_table(report["per_category"]))
    _print_case_outcomes(outcomes)
    for case in gate.declared_held:
        console.print(f"declared, did not flip: {case}")
    if result.declarations.ignored:
        ignored = ", ".join(sorted(result.declarations.ignored))
        console.print(
            "[yellow]Declarations of HEAD ignored, the tree has tracked changes:"
            f" {escape(ignored)}[/yellow]"
        )
    if gate.protected:
        console.print(f"Baseline under the current labels: {_protected_line(gate.protected)}")
    if report["throttled_requests"] > 0:
        console.print(
            f"[yellow]Throttled by the model provider: {report['throttled_requests']} requests"
            f" at concurrency {report['concurrency']}[/yellow]"
        )
    console.print(f"Report written to {report_path}")
    console.print(Panel("\n".join([_VERDICT_STYLES[gate.verdict], *_bullets(gate.reasons)])))
    if result.written:
        _print_written(result.written)
    if result.recording_refused:
        print_refusal("Recording refused.", result.recording_refused)


def _runs_table(per_run: list[dict[str, Any]]) -> Table:
    table = Table(show_header=True, header_style="bold")
    for column in ("Run", "P", "R", "F1", "TP", "FP", "FN", "TN"):
        table.add_column(column, justify="right")
    for index, metrics in enumerate(per_run, start=1):
        confusion = metrics["confusion_matrix"]
        table.add_row(
            str(index),
            *(f"{metrics[name]:.2f}" for name in ("precision", "recall", "f1")),
            *(str(confusion[name]) for name in ("tp", "fp", "fn", "tn")),
        )
    return table


def _category_table(per_category: dict[str, dict[str, Any]]) -> Table:
    table = Table(show_header=True, header_style="bold", title="All runs, per category")
    table.add_column("Category")
    for column in ("P", "R", "F1"):
        table.add_column(column, justify="right")
    for category, metrics in per_category.items():
        table.add_row(category, *(f"{metrics[name]:.2f}" for name in ("precision", "recall", "f1")))
    return table


def _print_case_outcomes(outcomes: CaseOutcomes) -> None:
    if outcomes.counts:
        counts = ", ".join(f"{count} {outcome}" for outcome, count in outcomes.counts.items())
        console.print(f"Cases: {counts}")
    if outcomes.rows:
        console.print(_outcome_table(outcomes.rows))
        console.print("P pass, F fail, - no verdict")
        if any(row.outcome == PARTIAL for row in outcomes.rows):
            console.print(
                "partial: wrong in every baseline run, right in some runs of this one, not gated"
            )


_OUTCOME_COLUMNS = (
    "Outcome",
    "Case",
    "Origin",
    "Target",
    "Label",
    "Baseline",
    "Run",
    "Replays",
    "Cause",
)


def _outcome_table(rows: list[JudgeOutcomeRow]) -> Table:
    table = Table(box=None, header_style="bold")
    for column in _OUTCOME_COLUMNS:
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            row.outcome,
            row.case,
            escape(row.origin),
            row.target,
            row.label or "-",
            row.baseline,
            row.run,
            row.replays,
            row.cause,
        )
    return table


def _print_written(baseline: JudgeBaseline) -> None:
    lines = [
        f"[bold green]Baseline recorded ({baseline.status}) to {JUDGE_BASELINE_PATH}.[/bold green]",
        *(
            f"- looked stable in the first recording and varied in the second: {case}"
            for case in baseline.disagreements
        ),
        _protected_line(baseline.protected),
        _NEXT_STEP[baseline.status],
    ]
    console.print(Panel("\n".join(lines)))


def _protected_line(protected: ProtectedCells) -> str:
    return (
        f"FAIL cases stable and correct: {protected.fail_stable_correct}/{protected.fail_total}, "
        f"PASS cases stable and correct: {protected.pass_stable_correct}/{protected.pass_total}, "
        f"unstable: {protected.unstable}"
    )


def _bullets(reasons: list[str]) -> list[str]:
    return [f"- {escape(reason)}" for reason in reasons]
