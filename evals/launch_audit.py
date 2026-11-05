"""One audit of one launch, shared by the CVE benchmark and the nuisance suite: connect to the
server, record its exchanges, run the graph under the attempt's own throttle breaker and provider
error classification, and read the server's health."""

import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any

from evals.cve_environments import TOOL_CALL_TIMEOUT, Launch, connect
from evals.cve_recording_client import Exchange, RecordingClient
from evals.eval_display import console
from evals.failure_text import FULL_DETAIL, ReportDetail
from evals.provider_errors import audit_failures_unwrapped, classified
from evals.server_health import ServerHealth, health_of
from mcp_auditor.adapters.llm_throttling import one_audit
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AttackContext, AuditReport
from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.graph.builder import build_graph

type Connect = Callable[..., AbstractAsyncContextManager[MCPClientPort]]


@dataclass(frozen=True)
class Auditor:
    llm: LLMPort
    judge_llm: LLMPort
    budget: int
    report_detail: ReportDetail = FULL_DETAIL
    connect: Connect = connect
    build_graph: Callable[..., Any] = build_graph


@dataclass(frozen=True)
class AuditShape:
    """What the graph audits and how far, each setting left None keeping the launch's own."""

    tools_filter: frozenset[str] | None
    chain_budget: int | None
    max_chain_steps: int | None
    tool_call_timeout: int | None


@dataclass(frozen=True)
class LaunchAudit:
    report: AuditReport
    exchanges: list[Exchange]
    health: ServerHealth


async def audit_launch(launch: Launch, auditor: Auditor, shape: AuditShape) -> LaunchAudit:
    """Raises `AuditFailed` bare on a provider error, whatever groups the client wraps it in."""
    timeout = _either(shape.tool_call_timeout, TOOL_CALL_TIMEOUT)
    with audit_failures_unwrapped(), open(os.devnull, "w") as devnull:
        async with auditor.connect(launch, devnull, tool_call_timeout=timeout) as client:
            recorder = RecordingClient(client)
            graph = auditor.build_graph(
                auditor.llm,
                AuditedServer(recorder),
                judge_llm=auditor.judge_llm,
                tools_filter=shape.tools_filter,
            )
            with one_audit():
                result = await classified(graph.ainvoke(_graph_input(launch, auditor, shape)))
            health = health_of(client, recorder.exchanges)
            return LaunchAudit(result["audit_report"], recorder.exchanges, health)


def _graph_input(launch: Launch, auditor: Auditor, shape: AuditShape) -> dict[str, object]:
    return {
        "target": f"{launch.command} {' '.join(launch.args)}",
        "test_budget": auditor.budget,
        "attack_context": AttackContext(),
        "chain_budget": _either(shape.chain_budget, launch.chain_budget),
        "max_chain_steps": _either(shape.max_chain_steps, launch.max_chain_steps),
    }


def _either(forced: int | None, own: int) -> int:
    return own if forced is None else forced


def print_lost_connections(label: str, health: ServerHealth) -> None:
    if health.lost_connection_responses > 0:
        console.print(
            f"[yellow]{label}: server connection lost on"
            f" {health.lost_connection_responses} call(s)[/yellow]"
        )
