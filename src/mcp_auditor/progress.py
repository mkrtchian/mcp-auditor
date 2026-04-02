from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TaskID, TextColumn

from mcp_auditor.domain.models import EvalResult, EvalVerdict, Severity
from mcp_auditor.domain.owasp import owasp_id_for
from mcp_auditor.domain.rendering import format_severity_breakdown


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

    def start(self) -> None:
        pass

    def stop(self) -> None:
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

    def start(self) -> None:
        if self._case_count == 0:
            self._console.print(f"{self._tool_label} \u2014 no cases")
            return
        self._progress.start()
        self._task_id = self._progress.add_task(self._tool_label, total=self._case_count)

    def stop(self) -> None:
        if self._case_count == 0:
            return
        self._progress.stop()
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
