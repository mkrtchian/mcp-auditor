import pytest

from evals.cve_recording_client import Exchange
from evals.server_health import NO_INCIDENTS, ServerHealth, health_of, lost_connection
from mcp_auditor.domain.models import ToolResponse


def _a_response(error_type: str | None, content: str) -> ToolResponse:
    return ToolResponse(content=content, is_error=error_type is not None, error_type=error_type)


_LOST = _a_response("McpError", "Connection closed")
_ANSWERED = _a_response(None, "ok")


class _NoisyClient:
    non_protocol_lines = 2


def test_healths_add_up_count_by_count():
    assert ServerHealth(2, 1) + ServerHealth(3, 0) == ServerHealth(5, 1)
    assert NO_INCIDENTS + ServerHealth(1, 4) == ServerHealth(1, 4)


def test_the_health_reads_the_client_count_and_the_lost_connections_of_the_calls():
    calls: list[Exchange] = [("read", {}, _ANSWERED), ("read", {}, _LOST)]

    assert health_of(_NoisyClient(), calls) == ServerHealth(2, 1)


def test_a_client_that_counts_no_line_reads_none():
    assert health_of(object(), [("read", {}, _ANSWERED)]) == NO_INCIDENTS


@pytest.mark.parametrize(
    ("error_type", "content", "lost"),
    [
        ("McpError", "Connection closed", True),
        ("ClosedResourceError", "", True),
        ("BrokenResourceError", "", True),
        ("McpError", "Invalid params", False),
        ("TimeoutError", "Tool call timed out after 2s", False),
        (None, "the flag", False),
    ],
    ids=["connection_closed", "closed_stream", "broken_stream", "other_mcp", "timeout", "ok"],
)
def test_a_lost_connection_is_read_from_the_pinned_responses(
    error_type: str | None, content: str, lost: bool
):
    assert lost_connection(_a_response(error_type, content)) is lost
