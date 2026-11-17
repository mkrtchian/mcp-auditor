import asyncio
from collections.abc import AsyncGenerator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from evals.cve.environments import Launch
from evals.cve.failure_text import FULL_DETAIL, ReportDetail
from evals.cve.launch_audit import Auditor
from mcp_auditor.adapters.llm_throttling import ThrottleBreaker, current_breaker
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    AuditReport,
    ToolDefinition,
    ToolResponse,
)
from mcp_auditor.domain.server_liveness import Relaunch, RelaunchCause
from tests.fakes import FakeLLM, FakeMCPClient
from tests.unit.cve.support import test_cve_grammar_given as grammar

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


def graph_reporting_its_relaunches(calls: int) -> FakeGraphs:
    """Each audit sends `calls` calls to the server, then returns a report holding the relaunches
    they led to, as the graph records them."""

    async def call(server: AuditedServer) -> AuditReport:
        attempts = [await server.attempt(_READ, _A_PAYLOAD) for _ in range(calls)]
        relaunches = [attempt.relaunch for attempt in attempts if attempt.relaunch is not None]
        return grammar.a_report().model_copy(update={"relaunches": relaunches})

    return FakeGraphs(call)


def a_report_with_relaunches(*succeeded: bool) -> AuditReport:
    relaunches = [
        Relaunch(
            tool_name="read",
            arguments={"path": "/x"},
            cause=RelaunchCause.LOST_CONNECTION,
            succeeded=outcome,
        )
        for outcome in succeeded
    ]
    return grammar.a_report().model_copy(update={"relaunches": relaunches})


def graph_raising(error: Exception) -> FakeGraphs:
    async def raise_error(_server: AuditedServer) -> AuditReport:
        raise error

    return FakeGraphs(raise_error)


@dataclass
class FakeConnect:
    """Stands in for `connect`. An error leaving the client comes out bare when `grouped` is off,
    as the session's owner lets it out, or wrapped in nested groups when it is on, the shape the
    MCP SDK's task groups give the error of an opening."""

    client: FakeMCPClient = field(default_factory=lambda: FakeMCPClient([]))
    grouped: bool = True
    timeouts: list[int] = field(default_factory=list[int])
    launches: list[Launch] = field(default_factory=list[Launch])

    @asynccontextmanager
    async def __call__(
        self, launch: Launch, _stderr: object, *, tool_call_timeout: int
    ) -> AsyncGenerator[FakeMCPClient]:
        self.timeouts.append(tool_call_timeout)
        self.launches.append(launch)
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


def a_client_whose_relaunch_fails() -> FakeMCPClient:
    """A client answering every call with a lost connection, whose every relaunch fails."""
    return _NoisyClient(non_protocol_lines=0, relaunch_answers=(False,))


class _NoisyClient(FakeMCPClient):
    def __init__(self, non_protocol_lines: int, relaunch_answers: Sequence[bool] = (True,)) -> None:
        lost = ToolResponse(content="Connection closed", is_error=True, error_type="McpError")
        super().__init__([_READ], {"read": lost}, relaunch_answers=relaunch_answers)
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
