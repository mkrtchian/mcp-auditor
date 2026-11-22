from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AuditCategory, AuditPayload, ToolDefinition
from mcp_auditor.domain.server_watch import TIMEOUTS_IN_A_ROW
from tests.fakes import FakeMCPClient
from tests.fakes.mcp_client import a_lost_connection_response, a_timeout_response

_PAYLOAD = AuditPayload(
    category=AuditCategory.INJECTION, description="probe", arguments={"input": "probe"}
)


async def a_server_taken_as_down(
    tool: ToolDefinition, *other_tools: ToolDefinition
) -> tuple[AuditedServer, FakeMCPClient]:
    """A server whose connection was lost on a first call to the tool, and whose relaunch failed."""
    client = FakeMCPClient(
        [tool, *other_tools], {tool.name: a_lost_connection_response()}, relaunch_answers=(False,)
    )
    server = AuditedServer(client)
    await server.attempt(tool, _PAYLOAD)
    return server, client


async def a_server_that_stopped(tool: ToolDefinition) -> AuditedServer:
    """A server that answers the ping, on which the tool timed out until it was stopped."""
    server = AuditedServer(FakeMCPClient([tool], {tool.name: a_timeout_response()}))
    for _ in range(TIMEOUTS_IN_A_ROW):
        await server.attempt(tool, _PAYLOAD)
    return server


def a_server_losing_its_connection(tool: ToolDefinition) -> AuditedServer:
    return AuditedServer(FakeMCPClient([tool], {tool.name: a_lost_connection_response()}))
