from __future__ import annotations

import json
from collections import Counter
from types import TracebackType
from typing import Self

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TaskID, TextColumn
from rich.status import Status
from rich.table import Table
from rich.text import Text

from mcp_auditor.domain.models import (
    AuditPayload,
    AuditReport,
    EvalResult,
    EvalVerdict,
    Severity,
    TestCase,
    TokenUsage,
)
from mcp_auditor.domain.owasp import owasp_id_for
from mcp_auditor.domain.rendering import format_severity_breakdown, render_summary


class AuditDisplay:
    def __init__(self, console: Console | None = None, ci_mode: bool = False) -> None:
        if console:
            self._console = console
        elif ci_mode:
            self._console = Console(force_terminal=False, no_color=True)
        else:
            self._console = Console()
        self._ci_mode = ci_mode

    def print_header(self, target_command: str) -> None:
        if self._ci_mode:
            return
        self._console.print(Panel(target_command, title="MCP Auditor"))

    def print_discovery(self, tool_count: int, tool_names: list[str]) -> None:
        if tool_count > 6:
            self._console.print(f"Discovered {tool_count} tools:")
            self._console.print(Columns(tool_names))
        else:
            names = ", ".join(tool_names)
            self._console.print(f"Discovered {tool_count} tools: {names}")

    def create_tool_progress(
        self,
        tool_index: int,
        tool_count: int,
        tool_name: str,
        case_count: int,
    ) -> ToolProgress | CIProgress:
        label = f"[{tool_index}/{tool_count}] {tool_name}"
        if self._ci_mode:
            return CIProgress(self._console, label)
        return ToolProgress(self._console, label, case_count)

    def print_summary(self, report: AuditReport) -> None:
        if self._ci_mode:
            self._console.print(render_summary(report))
            return
        table, total_pass, total_judged = _build_summary_table(report)
        score_line = _format_score_line(total_pass, total_judged)
        token_line = _format_token_usage(report.token_usage)
        panel = Panel(table, title="Results", subtitle=f"{score_line}  |  {token_line}")
        self._console.print(panel)

    def print_findings_recap(self, report: AuditReport) -> None:
        findings = sorted(report.findings, key=lambda f: f.severity, reverse=True)
        if not findings:
            return
        if self._ci_mode:
            self._print_findings_recap_ci(findings)
        else:
            self._print_findings_recap_rich(findings)

    def _print_findings_recap_ci(self, findings: list[EvalResult]) -> None:
        self._console.print("Findings:")
        for f in findings:
            owasp = owasp_id_for(f.category)
            category_display = f"{f.category} / {owasp}" if owasp else str(f.category)
            justification = _truncate(f.justification, 80)
            severity = f.severity.value.upper()
            line = f"  {severity}: {f.tool_name} > {category_display} \u2014 {justification}"
            self._console.print(line)

    def _print_findings_recap_rich(self, findings: list[EvalResult]) -> None:
        lines: list[Text] = []
        current_severity: Severity | None = None
        for f in findings:
            if f.severity != current_severity:
                current_severity = f.severity
                label = Text(f"\n  {f.severity.value.upper()}", style=_severity_style(f.severity))
                lines.append(label)
            owasp = owasp_id_for(f.category)
            category_display = f"{f.category} / {owasp}" if owasp else str(f.category)
            justification = _truncate(f.justification, 80)
            lines.append(Text(f"    {f.tool_name} > {category_display} \u2014 {justification}"))
        group = Text("\n").join(lines)
        self._console.print(Panel(group, title="Findings"))

    def print_dry_run_payloads(self, tool_name: str, cases: list[AuditPayload]) -> None:
        table = Table(title=f"Dry Run: {tool_name}")
        table.add_column("Category")
        table.add_column("Description")
        table.add_column("Arguments")
        for case in cases:
            table.add_row(case.category.value, case.description, json.dumps(case.arguments))
        self._console.print(table)

    def print_report_path(self, path: str) -> None:
        self._console.print(f"Report written to: {path}")

    def print_error(self, message: str) -> None:
        if self._ci_mode:
            self._console.print(f"Error: {message}")
        else:
            self._console.print(f"[red]Error: {message}[/red]")

    def status(self, message: str) -> Status | NullStatus:
        if self._ci_mode:
            return NullStatus()
        return self._console.status(message)


def _severity_style(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "dim",
    }[severity]


def _format_score_line(total_pass: int, total_judged: int) -> str:
    percentage = round(total_pass / total_judged * 100) if total_judged > 0 else 0
    bar_width = 20
    filled = round(bar_width * percentage / 100)
    empty = bar_width - filled
    bar = "\u2588" * filled + "\u2591" * empty
    if percentage >= 80:
        color = "green"
    elif percentage >= 60:
        color = "yellow"
    else:
        color = "red"
    return f"[{color}]Score: {total_pass}/{total_judged} {bar} {percentage}%[/{color}]"


def _truncate(text: str, max_length: int) -> str:
    if len(text) <= max_length:
        return text
    return text[: max_length - 1] + "\u2026"


def _build_summary_table(report: AuditReport) -> tuple[Table, int, int]:
    table = Table()
    table.add_column("Tool")
    table.add_column("Tests", justify="right")
    table.add_column("Pass", justify="right", style="green")
    table.add_column("Fail", justify="right")

    total_pass = 0
    total_judged = 0
    for tool_report in report.tool_reports:
        judged = [c for c in tool_report.cases if c.eval_result is not None]
        total = len(judged)
        passes = sum(
            1 for c in judged if c.eval_result and c.eval_result.verdict == EvalVerdict.PASS
        )
        fails = total - passes
        total_pass += passes
        total_judged += total
        fail_cell = _format_fail_cell(judged, fails)
        table.add_row(tool_report.tool.name, str(total), str(passes), fail_cell)

    return table, total_pass, total_judged


def _format_fail_cell(judged: list[TestCase], fails: int) -> Text | str:
    if fails == 0:
        return "0"
    severity_counts: Counter[Severity] = Counter(
        c.eval_result.severity
        for c in judged
        if c.eval_result is not None and c.eval_result.verdict == EvalVerdict.FAIL
    )
    breakdown = format_severity_breakdown(severity_counts)
    highest = max(severity_counts)
    style = _severity_style(highest)
    text = Text(f"{fails} ({breakdown})", style=style)
    return text


def _format_token_usage(usage: TokenUsage) -> str:
    return f"Tokens: {usage.input_tokens:,} in / {usage.output_tokens:,} out"


def format_failure_line(result: EvalResult) -> str:
    owasp = owasp_id_for(result.category)
    category_display = f"{result.category} / {owasp}" if owasp else str(result.category)
    return f"  \u2717 {category_display} ({result.severity}): {result.justification}"


def format_tool_summary(fail_count: int, pass_count: int, failures: list[EvalResult]) -> str:
    if fail_count == 0:
        return "\u2713 all passed"
    severity_counts: Counter[Severity] = Counter(f.severity for f in failures)
    breakdown = format_severity_breakdown(severity_counts)
    return f"\u2717 {fail_count} failed ({breakdown})"


class NullStatus:
    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        pass


class _ResultTracker:
    def __init__(self) -> None:
        self.fail_count = 0
        self.pass_count = 0
        self.failures: list[EvalResult] = []

    def record(self, result: EvalResult) -> None:
        if result.verdict == EvalVerdict.FAIL:
            self.fail_count += 1
            self.failures.append(result)
        else:
            self.pass_count += 1


class CIProgress:
    def __init__(self, console: Console, tool_label: str) -> None:
        self._console = console
        self._tool_label = tool_label
        self._tracker = _ResultTracker()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        t = self._tracker
        summary = format_tool_summary(t.fail_count, t.pass_count, t.failures)
        self._console.print(f"{self._tool_label}: {summary}")
        for failure in t.failures:
            self._console.print(format_failure_line(failure))

    def advance(self, result: EvalResult) -> None:
        self._tracker.record(result)


class ToolProgress:
    def __init__(self, console: Console, tool_label: str, case_count: int) -> None:
        self._console = console
        self._tool_label = tool_label
        self._case_count = case_count
        self._tracker = _ResultTracker()
        self._progress = Progress(
            TextColumn("{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
        )
        self._task_id: TaskID | None = None

    def __enter__(self) -> Self:
        if self._case_count == 0:
            self._console.print(f"{self._tool_label} — no cases")
            return self
        self._progress.__enter__()
        self._task_id = self._progress.add_task(self._tool_label, total=self._case_count)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._case_count == 0:
            return
        self._progress.__exit__(exc_type, exc_val, exc_tb)
        t = self._tracker
        summary = format_tool_summary(t.fail_count, t.pass_count, t.failures)
        style = "green" if t.fail_count == 0 else "red"
        self._console.print(f"[{style}]{summary}[/{style}]")

    def advance(self, result: EvalResult) -> None:
        self._tracker.record(result)
        if result.verdict == EvalVerdict.FAIL:
            self._progress.console.print(format_failure_line(result))
        if self._task_id is not None:
            self._progress.advance(self._task_id)
