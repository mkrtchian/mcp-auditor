"""One audit of one launch, shared by the detection suite and the nuisance suite: name the
server's container, connect to it, keep its exchanges and the points where the auditor relaunched
it, run the graph under the attempt's own throttle breaker and provider error classification, and
read the server's health.

The container is named at audit time so that the auditor can remove a blocked server before it
relaunches it (ADR 036): the client removes a declared container by the `--name` its `docker run`
sets. The name is a random token under the suite's label: a container name resolves by DNS on a
user-defined network, so it says nothing of the server or the flaw. A launch that already names
its container keeps its name. A relaunch that failed takes the server as down, which the suites
read as a failure to launch."""

from __future__ import annotations

import os
import secrets
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from rich.markup import escape

from evals.cve.environments import TOOL_CALL_TIMEOUT, Launch, connect
from evals.cve.exchange_log import Exchange, ExchangeLog
from evals.cve.failure_text import FULL_DETAIL, ReportDetail
from evals.cve.planting_base import LABEL
from evals.cve.provider_errors import audit_failures_unwrapped, classified
from evals.cve.server_health import ServerHealth, health_of
from evals.eval_display import console
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.adapters.llm_throttling import one_audit
from mcp_auditor.config import load_settings
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.container_name import Undecidable, declared_container_name
from mcp_auditor.domain.models import AttackContext, AuditReport
from mcp_auditor.domain.ports import LLMPort, MCPClientPort
from mcp_auditor.graph.builder import build_graph

if TYPE_CHECKING:
    from evals.cve.holdout_conditions import HoldoutConditions

type Connect = Callable[..., AbstractAsyncContextManager[MCPClientPort]]


class UndecidableLaunch(Exception):
    """A launch whose container name cannot be read: a configuration error, never a failure to
    launch, so it stops the run."""


class ServerTakenAsDown(Exception):
    """The auditor failed to relaunch the server: a failure to launch."""


@dataclass(frozen=True)
class Auditor:
    llm: LLMPort
    judge_llm: LLMPort
    budget: int
    report_detail: ReportDetail = FULL_DETAIL
    connect: Connect = connect
    build_graph: Callable[..., Any] = build_graph


def build_auditor(budget: int) -> Auditor:
    # Built before any container: a bad model configuration is a crash, never a run skipped,
    # which would read as a gate that cannot compare.
    settings = load_settings()
    return Auditor(create_llm(settings), create_judge_llm(settings), budget)


@dataclass(frozen=True)
class AuditShape:
    """What the graph audits and how far, each setting left None keeping the launch's own."""

    tools_filter: frozenset[str] | None
    chain_budget: int | None
    max_chain_steps: int | None
    tool_call_timeout: int | None


@dataclass(frozen=True)
class RunOverrides:
    """Uniform run conditions applied to every target or server, each setting left None keeping
    the launch's own."""

    chain_budget: int | None = None
    max_chain_steps: int | None = None
    tool_call_timeout: int | None = None
    audit_every_tool: bool = False

    @classmethod
    def of_holdout(cls, conditions: HoldoutConditions) -> RunOverrides:
        chain, steps = conditions.chain_budget, conditions.max_chain_steps
        timeout = conditions.tool_call_timeout
        # `require_ready` passed, so every setting is recorded.
        assert chain is not None and steps is not None and timeout is not None
        return cls(chain, steps, timeout)

    def shape(self, tools_filter: frozenset[str] | None) -> AuditShape:
        return AuditShape(
            None if self.audit_every_tool else tools_filter,
            self.chain_budget,
            self.max_chain_steps,
            self.tool_call_timeout,
        )


NO_OVERRIDES = RunOverrides()


@dataclass(frozen=True)
class LaunchAudit:
    report: AuditReport
    exchanges: list[Exchange]
    health: ServerHealth
    relaunched_after: list[int]  # the number of exchanges recorded at each relaunch


async def audit_launch(launch: Launch, auditor: Auditor, shape: AuditShape) -> LaunchAudit:
    """Raises `AuditFailed` bare on a provider error, whatever groups the client wraps it in,
    `UndecidableLaunch` before connecting, and `ServerTakenAsDown` once the graph returns."""
    timeout = _either(shape.tool_call_timeout, TOOL_CALL_TIMEOUT)
    container = named(launch)
    with audit_failures_unwrapped(), open(os.devnull, "w") as devnull:
        async with auditor.connect(container, devnull, tool_call_timeout=timeout) as client:
            recorder = ExchangeLog(client)
            graph = auditor.build_graph(
                auditor.llm,
                AuditedServer(recorder),
                judge_llm=auditor.judge_llm,
                tools_filter=shape.tools_filter,
            )
            with one_audit():
                result = await classified(graph.ainvoke(_graph_input(launch, auditor, shape)))
            report: AuditReport = result["audit_report"]
            health = health_of(client, recorder.exchanges, report)
    # Read on the relaunches, not on a gap, so a relaunch that failed after the last call counts.
    if any(not relaunch.succeeded for relaunch in report.relaunches):
        raise ServerTakenAsDown("the auditor failed to relaunch the server")
    return LaunchAudit(report, recorder.exchanges, health, recorder.relaunched_after)


def named(launch: Launch) -> Launch:
    if launch.args[:1] != ["run"]:
        raise UndecidableLaunch("the launch is not a docker run")
    match declared_container_name(launch.args):
        case Undecidable.NAME:
            raise UndecidableLaunch("an option before the image hides the container name")
        case str():
            return launch
        case None:
            name = f"{LABEL}-audit-{secrets.token_hex(6)}"
            return replace(launch, args=["run", "--name", name, *launch.args[1:]])


def _graph_input(launch: Launch, auditor: Auditor, shape: AuditShape) -> dict[str, object]:
    return {
        "server_command": f"{launch.command} {' '.join(launch.args)}",
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


def print_report_incidents(label: str, report: AuditReport, detail: ReportDetail) -> None:
    for missed in report.missed_model_calls:
        console.print(f"[yellow]{label}: {escape(detail.missed_call_detail(missed))}[/yellow]")
    throttled = report.provider_usage.throttled_requests
    if throttled > 0:
        console.print(
            f"[yellow]{label}: throttled {throttled} time(s)"
            " by the model provider (HTTP 429)[/yellow]"
        )
