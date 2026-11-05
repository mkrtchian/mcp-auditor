import asyncio
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from evals.cve_environments import Launch
from evals.failure_text import FULL_DETAIL, ReportDetail
from evals.launch_audit import Auditor
from mcp_auditor.adapters.llm_throttling import ThrottleBreaker, current_breaker
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    AuditReport,
    ToolDefinition,
    ToolResponse,
)
from tests.fakes import FakeLLM, FakeMCPClient
from tests.unit.support import test_cve_grammar_given as grammar

type _Invocation = Callable[[AuditedServer], Awaitable[AuditReport]]


class FakeGraphs:
    """Stands in for `build_graph`, recording what each graph was built with and invoked on."""

    def __init__(self, invocation: _Invocation) -> None:
        self.invocation = invocation
        self.tools_filters: list[frozenset[str] | None] = []
        self.graph_inputs: list[dict[str, object]] = []
        self.breakers: list[ThrottleBreaker | None] = []

    def __call__(self, _llm: object, server: AuditedServer, **kwargs: Any) -> "_FakeGraph":
        self.tools_filters.append(kwargs["tools_filter"])
        return _FakeGraph(self, server)


@dataclass(frozen=True)
class _FakeGraph:
    graphs: FakeGraphs
    server: AuditedServer

    async def ainvoke(self, graph_input: dict[str, object]) -> dict[str, object]:
        self.graphs.graph_inputs.append(graph_input)
        self.graphs.breakers.append(current_breaker())
        return {"audit_report": await self.graphs.invocation(self.server)}


def graph_reporting(reports: list[AuditReport]) -> FakeGraphs:
    """Each audit yields to the event loop once, then returns the next report."""

    async def report(_server: AuditedServer) -> AuditReport:
        await asyncio.sleep(0)
        return reports.pop(0)

    return FakeGraphs(report)


def graph_calling(lost_calls: int) -> FakeGraphs:
    """Each audit sends `lost_calls` calls to the server, then returns a report."""

    async def call(server: AuditedServer) -> AuditReport:
        for _ in range(lost_calls):
            await server.attempt(_READ, _A_PAYLOAD)
        return grammar.a_report()

    return FakeGraphs(call)


def graph_raising(error: Exception) -> FakeGraphs:
    async def raise_error(_server: AuditedServer) -> AuditReport:
        raise error

    return FakeGraphs(raise_error)


@dataclass
class FakeConnect:
    """Stands in for `connect`. An error leaving the client comes out wrapped in nested groups,
    as the MCP SDK's task groups wrap it, or bare when `grouped` is off, as it leaves a server
    noisy at shutdown."""

    client: FakeMCPClient = field(default_factory=lambda: FakeMCPClient([]))
    grouped: bool = True
    timeouts: list[int] = field(default_factory=list[int])

    @asynccontextmanager
    async def __call__(
        self, _launch: Launch, _stderr: object, *, tool_call_timeout: int
    ) -> AsyncGenerator[FakeMCPClient]:
        self.timeouts.append(tool_call_timeout)
        try:
            yield self.client
        except Exception as exc:
            if not self.grouped:
                raise
            raise ExceptionGroup("client", [ExceptionGroup("session", [exc])]) from None


def a_noisy_client(non_protocol_lines: int = 2) -> FakeMCPClient:
    """A client that read `non_protocol_lines` lines it could not parse, answering every call
    with a lost connection."""
    return _NoisyClient(non_protocol_lines)


class _NoisyClient(FakeMCPClient):
    def __init__(self, non_protocol_lines: int) -> None:
        lost = ToolResponse(content="Connection closed", is_error=True, error_type="McpError")
        super().__init__([_READ], {"read": lost})
        self.non_protocol_lines = non_protocol_lines


_READ = ToolDefinition(name="read", input_schema={})
_A_PAYLOAD = AuditPayload(
    category=AuditCategory.INPUT_VALIDATION, description="a read", arguments={"path": "/x"}
)


def an_auditor(
    report_detail: ReportDetail = FULL_DETAIL,
    graphs: FakeGraphs | None = None,
    connect: FakeConnect | None = None,
) -> Auditor:
    return Auditor(
        FakeLLM([]),
        FakeLLM([]),
        budget=10,
        report_detail=report_detail,
        connect=connect or FakeConnect(),
        build_graph=graphs or graph_reporting([grammar.a_report()]),
    )
