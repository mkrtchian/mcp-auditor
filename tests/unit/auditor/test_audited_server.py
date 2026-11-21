import pytest

from mcp_auditor.domain import (
    AuditCategory,
    AuditPayload,
    BlockedPayload,
    ToolDefinition,
    ToolResponse,
)
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.redaction import Redaction
from mcp_auditor.domain.server_liveness import Relaunch, RelaunchCause, UnsentCause, UnsentPayload
from mcp_auditor.domain.server_watch import TIMEOUTS_IN_A_ROW, SendAttempt
from tests.fakes import FakeMCPClient
from tests.fakes.mcp_client import a_lost_connection_response, a_timeout_response
from tests.unit.auditor.support.audited_servers import a_server_taken_as_down

_TOOL = ToolDefinition(name="run", description="Runs a command", input_schema={"type": "object"})


def _a_payload(arguments: dict[str, str]) -> AuditPayload:
    return AuditPayload(category=AuditCategory.INJECTION, description="probe", arguments=arguments)


async def test_attempt_refuses_a_destructive_payload_without_touching_the_server():
    client = FakeMCPClient([_TOOL])
    server = AuditedServer(client)

    attempt = await server.attempt(_TOOL, _a_payload({"command": "rm -rf /"}))

    assert attempt == SendAttempt(BlockedPayload(reason="destructive filesystem command: rm -rf"))
    assert client.calls == []
    assert client.pings == 0


async def test_attempt_refuses_an_unencodable_payload_without_touching_the_server():
    client = FakeMCPClient([_TOOL])
    server = AuditedServer(client)

    attempt = await server.attempt(_TOOL, _a_payload({"q": "\ud800"}))

    assert attempt.outcome == BlockedPayload(
        reason="argument q holds a character that cannot be encoded as UTF-8"
    )
    assert client.calls == []


async def test_attempt_returns_the_server_response_for_a_benign_payload():
    client = FakeMCPClient([_TOOL], responses={"run": ToolResponse(content="mcp-auditor-probe")})
    server = AuditedServer(client)

    attempt = await server.attempt(_TOOL, _a_payload({"command": "echo mcp-auditor-probe"}))

    assert attempt == SendAttempt(ToolResponse(content="mcp-auditor-probe"))


async def test_list_tools_returns_the_server_tools():
    server = AuditedServer(FakeMCPClient([_TOOL]))

    assert await server.list_tools() == [_TOOL]


_VALUE = "s3cr3t-t0ken-value"
_REDACTION = Redaction({"TOKEN": _VALUE})
_MARKER = "[value of TOKEN, redacted by mcp-auditor]"
_LEAKY_TOOL = ToolDefinition(
    name=f"read_{_VALUE}", description=f"Reads {_VALUE}", input_schema={"type": "object"}
)


async def test_attempt_redacts_a_response_holding_a_relayed_value():
    client = FakeMCPClient([_TOOL], responses={"run": ToolResponse(content=f"HOME=/x {_VALUE}")})
    server = AuditedServer(client, _REDACTION)

    attempt = await server.attempt(_TOOL, _a_payload({"command": "env"}))

    assert attempt.outcome == ToolResponse(content=f"HOME=/x {_MARKER}")


async def test_list_tools_returns_redacted_definitions():
    server = AuditedServer(FakeMCPClient([_LEAKY_TOOL]), _REDACTION)

    assert await server.list_tools() == [
        ToolDefinition(
            name=f"read_{_MARKER}", description=f"Reads {_MARKER}", input_schema={"type": "object"}
        )
    ]


async def test_attempt_calls_the_server_with_the_original_name_of_a_redacted_tool():
    client = FakeMCPClient([_LEAKY_TOOL])
    server = AuditedServer(client, _REDACTION)
    [redacted_tool] = await server.list_tools()

    await server.attempt(redacted_tool, _a_payload({"path": "a"}))

    assert client.calls == [(_LEAKY_TOOL.name, {"path": "a"})]


async def test_attempt_on_a_resumed_audit_still_calls_the_server_with_the_original_name():
    redacted_tool = await AuditedServer(FakeMCPClient([_LEAKY_TOOL]), _REDACTION).list_tools()
    client = FakeMCPClient([_LEAKY_TOOL])
    fresh_server = AuditedServer(client, _REDACTION)

    await fresh_server.attempt(redacted_tool[0], _a_payload({"path": "a"}))

    assert client.calls == [(_LEAKY_TOOL.name, {"path": "a"})]


async def test_list_tools_sends_the_control_ping_and_the_next_call_sends_none():
    client = FakeMCPClient([_TOOL])
    server = AuditedServer(client)

    await server.list_tools()
    assert client.pings == 1
    await server.attempt(_TOOL, _a_payload({"command": "ls"}))

    assert client.pings == 1


async def test_a_first_call_on_a_session_with_no_control_ping_sends_one():
    client = FakeMCPClient([_TOOL])
    server = AuditedServer(client)

    await server.attempt(_TOOL, _a_payload({"command": "ls"}))

    assert client.pings == 1
    assert len(client.calls) == 1


async def test_a_tool_timing_out_in_a_row_is_called_no_more():
    client = FakeMCPClient([_TOOL], responses={"run": a_timeout_response()})
    server = AuditedServer(client)
    for _ in range(TIMEOUTS_IN_A_ROW):
        await server.attempt(_TOOL, _a_payload({"command": "sleep 99"}))

    attempt = await server.attempt(_TOOL, _a_payload({"command": "ls"}))

    assert attempt == SendAttempt(UnsentPayload(UnsentCause.TOOL_TIMING_OUT))
    assert server.unsent_cause("run") is UnsentCause.TOOL_TIMING_OUT
    assert len(client.calls) == TIMEOUTS_IN_A_ROW


@pytest.mark.parametrize("relaunch_succeeds", [True, False])
async def test_a_lost_connection_relaunches_the_server_after_the_call(relaunch_succeeds: bool):
    lost = a_lost_connection_response()
    client = FakeMCPClient([_TOOL], responses={"run": lost}, relaunch_answers=(relaunch_succeeds,))
    server = AuditedServer(client)

    attempt = await server.attempt(_TOOL, _a_payload({"command": "kill 1"}))

    assert attempt == SendAttempt(
        lost,
        Relaunch(
            tool_name="run",
            arguments={"command": "kill 1"},
            cause=RelaunchCause.LOST_CONNECTION,
            succeeded=relaunch_succeeds,
        ),
    )


async def test_a_control_ping_follows_each_relaunch_at_once():
    client = FakeMCPClient([_TOOL], responses={"run": a_lost_connection_response()})
    server = AuditedServer(client)

    await server.attempt(_TOOL, _a_payload({"command": "kill 1"}))
    await server.attempt(_TOOL, _a_payload({"command": "kill 1"}))

    assert client.relaunches == 2
    assert client.pings == 3


async def test_a_failed_relaunch_takes_the_server_as_down_and_sends_no_more_call():
    other = ToolDefinition(name="list", description="Lists", input_schema={"type": "object"})
    server, client = await a_server_taken_as_down(_TOOL, other)

    later = await server.attempt(other, _a_payload({"path": "."}))

    assert server.taken_as_down
    assert later == SendAttempt(UnsentPayload(UnsentCause.SERVER_DOWN))
    assert len(client.calls) == 1
    assert client.pings == 1


def test_redacting_follows_the_redaction():
    assert not AuditedServer(FakeMCPClient([])).redacting
    assert AuditedServer(FakeMCPClient([]), _REDACTION).redacting
