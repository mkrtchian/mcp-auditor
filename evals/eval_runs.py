import asyncio
import os
import sys
import traceback
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from uuid import UUID

from langchain_core.tracers.context import collect_runs
from rich.progress import Progress, TaskID

from evals import eval_display as display
from evals.honeypots import HONEYPOTS, MERGED_GROUND_TRUTH, HoneypotConfig, audit_honeypots
from evals.judging import RunsOutcome
from evals.metrics import RunDetail, VerdictMap, build_run_detail
from mcp_auditor.domain.models import AuditReport

AnnouncedAudit = Callable[[HoneypotConfig, str | None], Awaitable[AuditReport]]
"""Prints its announcement, if any, once the audit holds its slot."""


@dataclass(frozen=True)
class CompletedRun:
    detail: RunDetail
    verdicts: VerdictMap
    report: AuditReport


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
    outcome = RunsOutcome()
    for index, run in enumerate(completed):
        if run is None:
            continue
        outcome.details.append(run.detail)
        outcome.verdict_maps.append(run.verdicts)
        outcome.audits.append((index, run.report))
    return outcome


async def _run_or_warn(
    audit: AnnouncedAudit, index: int, tracker: RunProgress
) -> CompletedRun | None:
    try:
        verdicts, report, trace_ids = await _run_one_eval(audit, index, tracker)
    except Exception:
        tracker.progress.console.print(
            f"[yellow]Warning: run {index + 1}/{tracker.total_runs} failed:[/yellow]"
        )
        traceback.print_exc(file=sys.stderr)
        tracker.advance(len(HONEYPOTS))
        return None
    detail = build_run_detail(index, verdicts, report, MERGED_GROUND_TRUTH)
    _post_langsmith_feedback(detail, trace_ids)
    display.print_run_result(detail, tracker.progress)
    return CompletedRun(detail, verdicts, report)


async def _run_one_eval(
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
    if not _tracing_enabled():
        return await audit
    with collect_runs() as collector:
        report = await audit
    if collector.traced_runs:
        trace_ids.append(collector.traced_runs[0].id)
    return report


def _tracing_enabled() -> bool:
    return bool(os.environ.get("LANGSMITH_TRACING") or os.environ.get("LANGCHAIN_TRACING_V2"))


def _post_langsmith_feedback(run_detail: RunDetail, trace_ids: list[UUID]) -> None:
    if not _tracing_enabled():
        return
    try:
        from langsmith import Client  # type: ignore[import-untyped]

        client = Client()
        for trace_id in trace_ids:
            client.create_feedback(trace_id, key="recall", score=run_detail.recall)  # pyright: ignore[reportUnknownMemberType]
            client.create_feedback(trace_id, key="precision", score=run_detail.precision)  # pyright: ignore[reportUnknownMemberType]
    except Exception:
        pass  # Best-effort: don't fail evals because of LangSmith
