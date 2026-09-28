"""One graded audit of a CVE target on its pinned server, for the gated session."""

import os
import subprocess
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from rich.console import Console
from rich.markup import escape

from evals.cve_environments import Launch, connect
from evals.cve_grammar import RunGrade, grade_run
from evals.cve_session import AuditTarget
from evals.cve_targets import CVETarget
from evals.metrics import blocked_reasons, refused_steps
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.config import load_settings
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AttackContext, AuditReport
from mcp_auditor.domain.ports import MCPClientPort
from mcp_auditor.graph.builder import build_graph

console = Console()


class LaunchError(Exception):
    """A pinned server failed to launch or install (infra, not a detection miss)."""


def audit_target(budget: int) -> AuditTarget:
    async def audit(target: CVETarget) -> RunGrade | None:
        grade: RunGrade | None = None
        try:
            with target.environment() as launch:
                report = await _audit(launch, target, budget)
                # Graded before __exit__ fires so a best-effort teardown error
                # cannot erase a completed run's grade.
                grade = grade_run(target, report)
                _print_incidents(target, report)
        except (LaunchError, subprocess.CalledProcessError) as exc:
            outcome = "run skipped" if grade is None else "teardown failed"
            console.print(f"[yellow]{target.cve_id} {outcome}:[/yellow] {exc}")
        return grade

    return audit


def _print_incidents(target: CVETarget, report: AuditReport) -> None:
    for reason in blocked_reasons(report):
        console.print(f"[yellow]{target.cve_id}: payload blocked, {reason}[/yellow]")
    for refused in refused_steps(report):
        console.print(
            f"[yellow]{target.cve_id}: refused by the model provider, {escape(refused)}[/yellow]"
        )


async def _audit(launch: Launch, target: CVETarget, budget: int) -> AuditReport:
    settings = load_settings()
    llm = create_llm(settings)
    judge_llm = create_judge_llm(settings)
    try:
        async with _silent_client(launch) as mcp_client:
            graph = build_graph(
                llm,
                AuditedServer(mcp_client),
                judge_llm=judge_llm,
                tools_filter=target.tools_filter,
            )
            result = await graph.ainvoke(  # pyright: ignore[reportUnknownMemberType]
                {
                    "target": f"{launch.command} {' '.join(launch.args)}",
                    "test_budget": budget,
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
