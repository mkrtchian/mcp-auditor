from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TaskID, TextColumn

from mcp_auditor.domain.models import EvalVerdict, JudgeResult, MissCause, Severity
from mcp_auditor.domain.owasp import category_with_owasp_id
from mcp_auditor.domain.relaunch_rendering import UNSENT_CAUSE_LABELS
from mcp_auditor.domain.rendering import format_severity_breakdown
from mcp_auditor.domain.server_liveness import UnsentCause

UNJUDGED_LINES = {
    MissCause.PROVIDER_REFUSAL: "  ? not judged, the model provider refused the judgment",
    MissCause.UNREADABLE_ANSWER: "  ? not judged, the model's answer was unreadable",
    MissCause.PROVIDER_THROTTLED: (
        "  ? not judged, the model provider throttled the judgment past every retry"
    ),
}


class CIProgress:
    def __init__(self, console: Console, tool_label: str) -> None:
        self._console = console
        self._tool_label = tool_label
        self._tracker = _ResultTracker()

    def start(self) -> None:
        pass

    def stop(self) -> None:
        t = self._tracker
        summary = format_tool_summary(t.fail_count, t.failures)
        self._console.print(f"{self._tool_label}: {summary}")
        for failure in t.failures:
            self._console.print(format_failure_line(failure))

    def advance(self, result: JudgeResult) -> None:
        self._tracker.record(result)

    def advance_blocked(self, reason: str) -> None:
        self._console.print(format_blocked_line(reason))

    def advance_unjudged(self, cause: MissCause) -> None:
        self._console.print(UNJUDGED_LINES[cause])

    def advance_unsent(self, cause: UnsentCause) -> None:
        if self._tracker.first_unsent_with(cause):
            self._console.print(format_unsent_line(cause))


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
        summary = format_tool_summary(t.fail_count, t.failures)
        style = "green" if t.fail_count == 0 else "red"
        self._console.print(f"[{style}]{summary}[/{style}]")

    def advance(self, result: JudgeResult) -> None:
        self._tracker.record(result)
        if result.verdict == EvalVerdict.FAIL:
            self._progress.console.print(format_failure_line(result))
        if self._task_id is not None:
            self._progress.advance(self._task_id)

    def advance_blocked(self, reason: str) -> None:
        self._progress.console.print(format_blocked_line(reason))
        if self._task_id is not None:
            self._progress.advance(self._task_id)

    def advance_unjudged(self, cause: MissCause) -> None:
        self._progress.console.print(UNJUDGED_LINES[cause])
        if self._task_id is not None:
            self._progress.advance(self._task_id)

    def advance_unsent(self, cause: UnsentCause) -> None:
        if self._tracker.first_unsent_with(cause):
            self._progress.console.print(format_unsent_line(cause))
        if self._task_id is not None:
            self._progress.advance(self._task_id)


class _ResultTracker:
    def __init__(self) -> None:
        self.fail_count = 0
        self.failures: list[JudgeResult] = []
        self._unsent_cause: UnsentCause | None = None

    def record(self, result: JudgeResult) -> None:
        if result.verdict == EvalVerdict.FAIL:
            self.fail_count += 1
            self.failures.append(result)

    def first_unsent_with(self, cause: UnsentCause) -> bool:
        """Every case after the first not sent is withheld too, so one line names them all."""
        first = cause != self._unsent_cause
        self._unsent_cause = cause
        return first


def format_failure_line(result: JudgeResult) -> str:
    category_display = category_with_owasp_id(result.category)
    return f"  \u2717 {category_display} ({result.severity}): {result.justification}"


def format_blocked_line(reason: str) -> str:
    return f"  \u2298 blocked by the guard: {reason}"


def format_unsent_line(cause: UnsentCause) -> str:
    return f"  \u2298 calls not sent from here on: {UNSENT_CAUSE_LABELS[cause]}"


def format_tool_summary(fail_count: int, failures: list[JudgeResult]) -> str:
    if fail_count == 0:
        return "\u2713 all passed"
    severity_counts: Counter[Severity] = Counter(f.severity for f in failures)
    breakdown = format_severity_breakdown(severity_counts)
    return f"\u2717 {fail_count} failed ({breakdown})"
