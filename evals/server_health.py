"""What the server under audit did besides answering: the lines it wrote that the MCP client
could not parse, and the calls it answered with a lost connection. Report-only, no statistic,
gate or baseline reads them."""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from evals.cve_recording_client import Exchange
from mcp_auditor.domain.models import ToolResponse

# A server gone mid-call looks like an ordinary error: SDK 1.30 turns a call in flight when the
# server exits into an McpError reading "Connection closed", and the stdio transport surfaces a
# closed or broken stream under anyio's own error names. Any other McpError (invalid params, a
# removed tool) and a TimeoutError on a live server are ordinary responses.
LOST_CONNECTION_RESPONSES: tuple[tuple[str, str | None], ...] = (
    ("McpError", "Connection closed"),
    ("ClosedResourceError", None),
    ("BrokenResourceError", None),
)


@dataclass(frozen=True)
class ServerHealth:
    non_protocol_lines: int
    lost_connection_responses: int

    def __add__(self, other: "ServerHealth") -> "ServerHealth":
        return ServerHealth(
            self.non_protocol_lines + other.non_protocol_lines,
            self.lost_connection_responses + other.lost_connection_responses,
        )


NO_INCIDENTS = ServerHealth(0, 0)


@runtime_checkable
class CountsNonProtocolLines(Protocol):
    @property
    def non_protocol_lines(self) -> int: ...


def health_of(client: object, calls: Sequence[Exchange]) -> ServerHealth:
    # `connect` yields an `MCPClientPort`, whose annotation is fingerprinted into every fixture,
    # so the count is read through the Protocol rather than a narrowed return type.
    lines = client.non_protocol_lines if isinstance(client, CountsNonProtocolLines) else 0
    return ServerHealth(lines, sum(lost_connection(response) for _, _, response in calls))


def lost_connection(response: ToolResponse) -> bool:
    return response.is_error and any(
        response.error_type == error_type and (content is None or response.content == content)
        for error_type, content in LOST_CONNECTION_RESPONSES
    )
