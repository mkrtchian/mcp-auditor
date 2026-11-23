import asyncio
import sys
import traceback
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from uuid import UUID

from langchain_core.tracers.context import collect_runs
from rich.progress import Progress, TaskID

from evals import eval_display as display
from evals.honeypot.decision import CompletedRun, RunsOutcome
from evals.honeypots import HONEYPOTS, HoneypotConfig, audit_honeypots
from evals.metrics import RunDetail, VerdictMap
from evals.tracing import tracing_enabled
from mcp_auditor.domain.models import AuditReport

AnnouncedAudit = Callable[[HoneypotConfig, str | None], Awaitable[AuditReport]]
"""Prints its announcement, if any, once the audit holds its slot."""


@dataclass(frozen=True)
class RunProgress:
    progress: Progress
    task: TaskID
    total_runs: int

    def advance(self, steps: int = 1) -> None:
        self.progress.advance(self.task, advance=steps)


async def run_all(audit: AnnouncedAudit, runs: int) -> RunsOutcome:
    """Runs side by side, folded into the outcome in run index order."""
    with Progress(console=display.console) as progress:
        task = progress.add_task("Running evals", total=runs * len(HONEYPOTS))
        tracker = RunProgress(progress, task, runs)
        completed = await asyncio.gather(
            *(_run_or_warn(audit, index, tracker) for index in range(runs))
        )
    return RunsOutcome([run for run in completed if run is not None])


async def _run_or_warn(
    audit: AnnouncedAudit, index: int, tracker: RunProgress
) -> CompletedRun | None:
    try:
        verdicts, report, trace_ids = await _run_one(audit, index, tracker)
    except Exception:
        tracker.progress.console.print(
            f"[yellow]Warning: run {index + 1}/{tracker.total_runs} failed:[/yellow]"
        )
        traceback.print_exc(file=sys.stderr)
        tracker.advance(len(HONEYPOTS))
        return None
    run = CompletedRun.of(index, verdicts, report)
    _post_langsmith_feedback(run.detail, trace_ids)
    display.print_run_result(run.detail, tracker.progress)
    return run


async def _run_one(
    audit: AnnouncedAudit, index: int, tracker: RunProgress
) -> tuple[VerdictMap, AuditReport, list[UUID]]:
    trace_ids: list[UUID] = []

    async def audit_in_run(honeypot: HoneypotConfig) -> AuditReport:
        announcement = f"  Run {index + 1}: auditing [bold]{honeypot.name}[/bold]..."
        report = await _traced(audit(honeypot, announcement), trace_ids)
        tracker.advance()
        return report

    verdicts, report = await audit_honeypots(audit_in_run)
    return verdicts, report, trace_ids


async def _traced(audit: Awaitable[AuditReport], trace_ids: list[UUID]) -> AuditReport:
    if not tracing_enabled():
        return await audit
    with collect_runs() as collector:
        report = await audit
    if collector.traced_runs:
        trace_ids.append(collector.traced_runs[0].id)
    return report


def _post_langsmith_feedback(run_detail: RunDetail, trace_ids: list[UUID]) -> None:
    if not tracing_enabled():
        return
    try:
        from langsmith import Client

        client = Client()
        for trace_id in trace_ids:
            client.create_feedback(trace_id, key="recall", score=run_detail.recall)
            client.create_feedback(trace_id, key="precision", score=run_detail.precision)
    except Exception:
        pass  # Best-effort: don't fail evals because of LangSmith
