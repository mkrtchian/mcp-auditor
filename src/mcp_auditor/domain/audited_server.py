from mcp_auditor.domain.models import AuditPayload, BlockedPayload, ToolDefinition, ToolResponse
from mcp_auditor.domain.payload_safety import destructive_reason
from mcp_auditor.domain.ports import MCPClientPort
from mcp_auditor.domain.redaction import Redaction

_NO_REDACTION = Redaction.none()


class AuditedServer:
    """The only reach the graph has into the server under audit (ADR 013)."""

    def __init__(self, client: MCPClientPort, redaction: Redaction = _NO_REDACTION) -> None:
        self._client = client
        self._redaction = redaction
        self._original_names: dict[str, str] | None = None

    @property
    def redacting(self) -> bool:
        return self._redaction.active

    async def list_tools(self) -> list[ToolDefinition]:
        originals = await self._client.list_tools()
        redacted = [self._redaction.tool(tool) for tool in originals]
        self._original_names = {
            redacted_tool.name: original.name
            for redacted_tool, original in zip(redacted, originals, strict=True)
        }
        return redacted

    async def attempt(
        self, tool: ToolDefinition, payload: AuditPayload
    ) -> ToolResponse | BlockedPayload:
        reason = destructive_reason(payload.arguments)
        if reason is not None:
            return BlockedPayload(reason=reason)
        if self._original_names is None and self.redacting:
            # A resumed audit takes its tools from the checkpoint, never from list_tools.
            await self.list_tools()
        original_name = (self._original_names or {}).get(tool.name, tool.name)
        response = await self._client.call_tool(original_name, payload.arguments)
        return self._redaction.response(response)
