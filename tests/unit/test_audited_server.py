from mcp_auditor.domain import (
    AuditCategory,
    AuditPayload,
    BlockedPayload,
    ToolDefinition,
    ToolResponse,
)
from mcp_auditor.domain.audited_server import AuditedServer
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
