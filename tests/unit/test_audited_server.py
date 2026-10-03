from mcp_auditor.domain import (
    AuditCategory,
    AuditPayload,
    BlockedPayload,
    ToolDefinition,
    ToolResponse,
)
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.redaction import Redaction
from tests.fakes import FakeMCPClient

_TOOL = ToolDefinition(name="run", description="Runs a command", input_schema={"type": "object"})


def _a_payload(arguments: dict[str, str]) -> AuditPayload:
    return AuditPayload(category=AuditCategory.INJECTION, description="probe", arguments=arguments)


async def test_attempt_refuses_a_destructive_payload_without_touching_the_server():
    client = FakeMCPClient([_TOOL])
    server = AuditedServer(client)

    outcome = await server.attempt(_TOOL, _a_payload({"command": "rm -rf /"}))

    assert outcome == BlockedPayload(reason="destructive filesystem command: rm -rf")
    assert client.calls == []


async def test_attempt_returns_the_server_response_for_a_benign_payload():
    client = FakeMCPClient([_TOOL], responses={"run": ToolResponse(content="mcp-auditor-probe")})
    server = AuditedServer(client)

    outcome = await server.attempt(_TOOL, _a_payload({"command": "echo mcp-auditor-probe"}))

    assert outcome == ToolResponse(content="mcp-auditor-probe")


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

    outcome = await server.attempt(_TOOL, _a_payload({"command": "env"}))

    assert outcome == ToolResponse(content=f"HOME=/x {_MARKER}")


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


def test_redacting_follows_the_redaction():
    assert not AuditedServer(FakeMCPClient([])).redacting
    assert AuditedServer(FakeMCPClient([]), _REDACTION).redacting
