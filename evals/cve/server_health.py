"""What the audited server did besides answering: the lines it wrote that the MCP client
could not parse, the calls it answered with a lost connection, the times the auditor relaunched
it, and the test cases and chains the auditor did not send once it stopped calling a tool or took
the server as down (ADR 036). Report-only, no statistic, grading, retry, gate or baseline reads
them."""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from evals.cve.exchange_log import Exchange
from mcp_auditor.domain.models import AuditReport
from mcp_auditor.domain.server_watch import is_lost_connection


@dataclass(frozen=True)
class ServerHealth:
    non_protocol_lines: int
    lost_connection_responses: int
    relaunches: int = 0
    unsent_calls: int = 0

    def __add__(self, other: "ServerHealth") -> "ServerHealth":
        return ServerHealth(
            self.non_protocol_lines + other.non_protocol_lines,
            self.lost_connection_responses + other.lost_connection_responses,
            self.relaunches + other.relaunches,
            self.unsent_calls + other.unsent_calls,
        )


NO_INCIDENTS = ServerHealth(0, 0, 0, 0)


@runtime_checkable
class CountsNonProtocolLines(Protocol):
    @property
    def non_protocol_lines(self) -> int: ...


def health_of(client: object, calls: Sequence[Exchange], report: AuditReport) -> ServerHealth:
    # `connect` yields an `MCPClientPort`, whose annotation is fingerprinted into every fixture,
    # so the count is read through the Protocol rather than a narrowed return type.
    lines = client.non_protocol_lines if isinstance(client, CountsNonProtocolLines) else 0
    return ServerHealth(
        lines,
        sum(is_lost_connection(response) for _, _, response in calls),
        len(report.relaunches),
        _unsent_calls(report),
    )


def _unsent_calls(report: AuditReport) -> int:
    gaps = [tool.coverage_gap for tool in report.tool_reports if tool.coverage_gap is not None]
    return sum(gap.unsent_cases + gap.unsent_chains for gap in gaps)
