from dataclasses import dataclass

from mcp_auditor.adapters.log_redaction import redacted_sdk_logging
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.adapters.server_launch import ServerLaunch
from mcp_auditor.adapters.stderr_capture import RedactingStderr
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import AuditCategory, AuditPayload, ToolResponse
from mcp_auditor.domain.relayed_environment import RelayedEnvironment, RelayRequest
from tests.integration.support.support_servers import ENV_ECHO_SERVER_PATH

NAME = "ECHO_TOKEN"
VALUE = "relayed-s3cr3t-4f9a"


@dataclass(frozen=True)
class Echo:
    response: str
    stderr: str


async def echoed_through_the_audit_boundaries(
    request: RelayRequest, *, relaunched: bool = False
) -> Echo:
    """The server echoes the variable on every channel, read the way `Audit.run` reads them,
    and echoes it again after a relaunch when `relaunched`."""
    relayed = RelayedEnvironment.resolved(request, {NAME: VALUE})
    launch = ServerLaunch.unconfined(
        "uv", ["run", "python", str(ENV_ECHO_SERVER_PATH)], relayed=relayed
    )
    redaction = relayed.redaction()
    with RedactingStderr(redaction) as stderr, redacted_sdk_logging(redaction):
        async with StdioMCPClient.connect(launch, errlog=stderr.writer) as client:
            server = AuditedServer(client, redaction)
            tools = await server.list_tools()
            payload = AuditPayload(
                category=AuditCategory.INFO_LEAKAGE, description="echo", arguments={"name": NAME}
            )
            response = (await server.attempt(tools[0], payload)).outcome
            if relaunched:
                assert await client.relaunch()
                response = (await server.attempt(tools[0], payload)).outcome
        assert isinstance(response, ToolResponse)
        return Echo(response.content, stderr.text())
