from __future__ import annotations

import json
from collections import Counter
from types import TracebackType
from typing import Self

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TaskID, TextColumn
from rich.status import Status
from rich.table import Table

from mcp_auditor.domain.models import AuditPayload, AuditReport, EvalResult, EvalVerdict, TokenUsage


def format_failure_line(result: EvalResult) -> str:
    return f"  \u2717 {result.category} ({result.severity}): {result.justification}"


def format_tool_summary(fail_count: int, pass_count: int, failures: list[EvalResult]) -> str:
    if fail_count == 0:
        return "\u2713 all passed"
    severity_counts = Counter(f.severity.value for f in failures)
    breakdown = ", ".join(f"{count} {sev}" for sev, count in severity_counts.items())
    return f"\u2717 {fail_count} failed ({breakdown})"


class ToolProgress:
    def __init__(self, console: Console, tool_label: str, case_count: int) -> None:
        self._console = console
        self._tool_label = tool_label
        self._case_count = case_count
        self._progress = Progress(
            TextColumn("{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
        )
        self._fail_count = 0
        self._pass_count = 0
        self._failures: list[EvalResult] = []
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
        summary = format_tool_summary(self._fail_count, self._pass_count, self._failures)
        style = "green" if self._fail_count == 0 else "red"
        self._console.print(f"[{style}]{summary}[/{style}]")

    def advance(self, result: EvalResult) -> None:
        if result.verdict == EvalVerdict.FAIL:
            self._fail_count += 1
            self._failures.append(result)
            self._progress.console.print(format_failure_line(result))
        else:
            self._pass_count += 1
        if self._task_id is not None:
            self._progress.advance(self._task_id)


class AuditDisplay:
    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    def print_header(self, target_command: str) -> None:
        self._console.print(Panel(target_command, title="MCP Auditor"))

    def print_discovery(self, tool_count: int, tool_names: list[str]) -> None:
        names = ", ".join(tool_names)
        self._console.print(f"Discovered {tool_count} tools: {names}")

    def create_tool_progress(
        self,
        tool_index: int,
        tool_count: int,
        tool_name: str,
        case_count: int,
    ) -> ToolProgress:
        label = f"[{tool_index}/{tool_count}] {tool_name}"
        return ToolProgress(self._console, label, case_count)

    def print_summary(self, report: AuditReport) -> None:
        table = Table()
        table.add_column("Tool")
        table.add_column("Tests", justify="right")
        table.add_column("Pass", justify="right", style="green")
        table.add_column("Fail", justify="right", style="red")

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
            table.add_row(tool_report.tool.name, str(total), str(passes), str(fails))

        percentage = round(total_pass / total_judged * 100) if total_judged > 0 else 0
        score_line = f"Score: {total_pass}/{total_judged} ({percentage}%)"
        token_line = _format_token_usage(report.token_usage)

        panel = Panel(table, title="Results", subtitle=f"{score_line}  |  {token_line}")
        self._console.print(panel)

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
        self._console.print(f"[red]Error: {message}[/red]")

    def status(self, message: str) -> Status:
        return self._console.status(message)


def _format_token_usage(usage: TokenUsage) -> str:
    return f"Tokens: {usage.input_tokens:,} in / {usage.output_tokens:,} out"
