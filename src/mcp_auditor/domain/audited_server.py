from mcp_auditor.domain.models import AuditPayload, BlockedPayload, ToolDefinition, ToolResponse
from mcp_auditor.domain.payload_safety import destructive_reason
from mcp_auditor.domain.ports import MCPClientPort


class AuditedServer:
    """The only reach the graph has into the server under audit (ADR 013)."""

    def __init__(self, client: MCPClientPort) -> None:
        self._client = client

    async def list_tools(self) -> list[ToolDefinition]:
        return await self._client.list_tools()

    async def attempt(
        self, tool: ToolDefinition, payload: AuditPayload
    ) -> ToolResponse | BlockedPayload:
        reason = destructive_reason(payload.arguments)
        if reason is not None:
            return BlockedPayload(reason=reason)
        return await self._client.call_tool(tool.name, payload.arguments)
