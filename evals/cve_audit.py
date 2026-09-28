"""One graded audit of a CVE target on its pinned server, for the gated session."""

import os
import subprocess
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

from rich.console import Console
from rich.markup import escape

from evals.concurrency import bounded, entered_in_thread
from evals.cve_environments import Launch, connect
from evals.cve_grammar import RunGrade, grade_run
from evals.cve_session import AuditTarget
from evals.cve_targets import CVETarget
from evals.metrics import SessionThrottles, blocked_reasons, refused_steps
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.config import load_settings
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AttackContext, AuditReport
from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.graph.builder import build_graph

console = Console()

# A policy refusal stops a step, so the run says nothing of detection. The generated prompts
# differ from one audit to the next, so a new attempt usually passes the provider's filter.
REFUSAL_ATTEMPTS = 3


class LaunchError(Exception):
    """A pinned server failed to launch or install (infra, not a detection miss)."""


@dataclass(frozen=True)
class _Auditor:
    llm: LLMPort
    judge_llm: LLMPort
    budget: int


def audit_target(budget: int, concurrency: int, throttles: SessionThrottles) -> AuditTarget:
    # Built once, before any container: a bad model configuration is a crash, never a
    # run skipped, which would read as a gate that cannot compare.
    settings = load_settings()
    auditor = _Auditor(create_llm(settings), create_judge_llm(settings), budget)

    async def audit(target: CVETarget) -> RunGrade | None:
        return await graded_despite_refusals(target, lambda: _attempt(target, auditor, throttles))

    return bounded(audit, concurrency)


@dataclass(frozen=True)
class RefusedAttempt:
    """An audit whose report holds a step the model provider refused."""


async def graded_despite_refusals(
    target: CVETarget, attempt: Callable[[], Awaitable[RunGrade | RefusedAttempt | None]]
) -> RunGrade | None:
    """The first attempt not refused grades the run. None when every attempt is refused."""
    for number in range(1, REFUSAL_ATTEMPTS + 1):
        outcome = await attempt()
        if not isinstance(outcome, RefusedAttempt):
            return outcome
        console.print(
            f"[yellow]{target.cve_id}: attempt {number}/{REFUSAL_ATTEMPTS} refused by the"
            " model provider, not graded[/yellow]"
        )
    console.print(
        f"[yellow]{target.cve_id} run skipped:[/yellow] refused by the model provider"
        f" at all {REFUSAL_ATTEMPTS} attempts"
    )
    return None


async def _attempt(
    target: CVETarget, auditor: _Auditor, throttles: SessionThrottles
) -> RunGrade | RefusedAttempt | None:
    outcome: RunGrade | RefusedAttempt | None = None
    try:
        async with entered_in_thread(target.environment()) as launch:
            report = await _audit(launch, target, auditor)
            throttles.count(report)
            _print_incidents(target, report)
            if report.refused_steps:
                outcome = RefusedAttempt()
            else:
                # Graded before __exit__ fires so a best-effort teardown error
                # cannot erase a completed run's grade.
                outcome = grade_run(target, report)
                console.print(f"{target.cve_id}: {outcome.status}")
    except (LaunchError, subprocess.CalledProcessError) as exc:
        failure = "run skipped" if outcome is None else "teardown failed"
        console.print(f"[yellow]{target.cve_id} {failure}:[/yellow] {exc}")
    return outcome


def _print_incidents(target: CVETarget, report: AuditReport) -> None:
    for reason in blocked_reasons(report):
        console.print(f"[yellow]{target.cve_id}: payload blocked, {reason}[/yellow]")
    for refused in refused_steps(report):
        console.print(
            f"[yellow]{target.cve_id}: refused by the model provider, {escape(refused)}[/yellow]"
        )
    throttled = report.provider_usage.throttled_requests
    if throttled > 0:
        console.print(
            f"[yellow]{target.cve_id}: throttled {throttled} time(s)"
            " by the model provider (HTTP 429)[/yellow]"
        )


async def _audit(launch: Launch, target: CVETarget, auditor: _Auditor) -> AuditReport:
    try:
        async with _silent_client(launch) as mcp_client:
            graph = build_graph(
                auditor.llm,
                AuditedServer(mcp_client),
                judge_llm=auditor.judge_llm,
                tools_filter=target.tools_filter,
            )
            result = await graph.ainvoke(  # pyright: ignore[reportUnknownMemberType]
                {
                    "target": f"{launch.command} {' '.join(launch.args)}",
                    "test_budget": auditor.budget,
                    "attack_context": AttackContext(),
                    "chain_budget": launch.chain_budget,
                    "max_chain_steps": launch.max_chain_steps,
                }
            )
            return result["audit_report"]
    except Exception as exc:
        raise LaunchError(str(exc)) from exc


@asynccontextmanager
async def _silent_client(launch: Launch) -> AsyncIterator[MCPClientPort]:
    with open(os.devnull, "w") as devnull:
        async with connect(launch, devnull) as client:
            yield client
