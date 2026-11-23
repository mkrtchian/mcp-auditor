from pathlib import Path

from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from evals.cell_grid import PARTIAL
from evals.eval_display import (
    PARTIAL_LEGEND,
    RECORDING_NEXT_STEP,
    console,
    print_declarations,
    print_outcome,
    print_refusal,
    print_throttles,
)
from evals.gate import ProtectedCells
from evals.judge.baseline import JUDGE_BASELINE_PATH, JudgeBaseline
from evals.judge.metrics import JudgeMetrics
from evals.judge.outcomes import CaseOutcomes, JudgeOutcomeRow
from evals.judge.report import JudgeReport
from evals.judge.session_model import JudgeSessionResult
from mcp_auditor.domain.models import AuditCategory


def print_summary(
    result: JudgeSessionResult, report: JudgeReport, report_path: Path, outcomes: CaseOutcomes
) -> None:
    gate = result.gate
    status = f", baseline {gate.baseline_status}" if gate.baseline_status else ""
    console.print(f"Gate mode: [bold]{gate.mode}[/bold]{status}")
    console.print(Panel(_runs_table(report.per_run), title="Judge Eval Diagnostics"))
    console.print(_category_table(report.per_category))
    _print_case_outcomes(outcomes)
    print_declarations(gate.declared_held, result.declarations.ignored)
    if gate.protected:
        console.print(f"Baseline under the current labels: {_protected_line(gate.protected)}")
    print_throttles(report.throttled_requests, report.concurrency)
    console.print(f"Report written to {report_path}")
    print_outcome(gate.outcome, gate.reasons)
    if result.written:
        _print_written(result.written)
    if result.recording_refused:
        print_refusal("Recording refused.", result.recording_refused)


def _runs_table(per_run: list[JudgeMetrics]) -> Table:
    table = Table(show_header=True, header_style="bold")
    for column in ("Run", "P", "R", "F1", "TP", "FP", "FN", "TN"):
        table.add_column(column, justify="right")
    for index, metrics in enumerate(per_run, start=1):
        confusion = metrics.confusion_matrix
        table.add_row(
            str(index),
            *(f"{score:.2f}" for score in (metrics.precision, metrics.recall, metrics.f1)),
            *(str(count) for count in (confusion.tp, confusion.fp, confusion.fn, confusion.tn)),
        )
    return table


def _category_table(per_category: dict[AuditCategory, JudgeMetrics]) -> Table:
    table = Table(show_header=True, header_style="bold", title="All runs, per category")
    table.add_column("Category")
    for column in ("P", "R", "F1"):
        table.add_column(column, justify="right")
    for category, metrics in per_category.items():
        scores = (metrics.precision, metrics.recall, metrics.f1)
        table.add_row(category.value, *(f"{score:.2f}" for score in scores))
    return table


def _print_case_outcomes(outcomes: CaseOutcomes) -> None:
    if outcomes.counts:
        counts = ", ".join(f"{count} {outcome}" for outcome, count in outcomes.counts.items())
        console.print(f"Cases: {counts}")
    if outcomes.rows:
        console.print(_outcome_table(outcomes.rows))
        console.print("P pass, F fail, - no verdict")
        if any(row.outcome == PARTIAL for row in outcomes.rows):
            console.print(PARTIAL_LEGEND)


_OUTCOME_COLUMNS = (
    "Outcome",
    "Case",
    "Origin",
    "Tool/category",
    "Label",
    "Baseline",
    "Run",
    "Retests",
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
            row.tool_category,
            row.label or "-",
            row.baseline,
            row.run,
            row.retests,
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
        RECORDING_NEXT_STEP[baseline.status],
    ]
    console.print(Panel("\n".join(lines)))


def _protected_line(protected: ProtectedCells) -> str:
    return (
        f"FAIL cases stable and correct: {protected.fail_stable_correct}/{protected.fail_total}, "
        f"PASS cases stable and correct: {protected.pass_stable_correct}/{protected.pass_total}, "
        f"unstable: {protected.unstable}"
    )
