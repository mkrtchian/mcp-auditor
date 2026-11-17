from typing import Any

from mcp_auditor.domain.models import AuditPayload, BlockedPayload, ToolDefinition, ToolResponse
from mcp_auditor.domain.payload_safety import destructive_reason, unsendable_reason
from mcp_auditor.domain.ports import MCPClientPort
from mcp_auditor.domain.redaction import Redaction
from mcp_auditor.domain.server_liveness import Relaunch, UnsentCause, UnsentPayload
from mcp_auditor.domain.server_watch import SendAttempt, ServerWatch, WatchStep

_NO_REDACTION = Redaction.none()


class AuditedServer:
    """The only reach the graph has into the audited server (ADR 013). It guards each payload,
    and watches the server (ADR 036): it pings it, relaunches it, and withholds the calls of a
    tool it stopped or of a server it took as down."""

    def __init__(self, client: MCPClientPort, redaction: Redaction = _NO_REDACTION) -> None:
        self._client = client
        self._redaction = redaction
        self._original_names: dict[str, str] | None = None
        self._watch = ServerWatch()
        self._control_ping_sent = False

    @property
    def redacting(self) -> bool:
        return self._redaction.active

    @property
    def taken_as_down(self) -> bool:
        return self._watch.taken_as_down

    def unsent_cause(self, tool_name: str) -> UnsentCause | None:
        return self._watch.unsent_cause(tool_name)

    async def list_tools(self) -> list[ToolDefinition]:
        originals = await self._client.list_tools()
        redacted = [self._redaction.tool(tool) for tool in originals]
        self._original_names = {
            redacted_tool.name: original.name
            for redacted_tool, original in zip(redacted, originals, strict=True)
        }
        await self._send_control_ping()
        return redacted

    async def attempt(self, tool: ToolDefinition, payload: AuditPayload) -> SendAttempt:
        reason = destructive_reason(payload.arguments) or unsendable_reason(payload.arguments)
        if reason is not None:
            return SendAttempt(BlockedPayload(reason=reason))
        unsent = self._watch.unsent_cause(tool.name)
        if unsent is not None:
            return SendAttempt(UnsentPayload(unsent))
        await self._ready_for_a_call()
        original_name = (self._original_names or {}).get(tool.name, tool.name)
        response = await self._client.call_tool(original_name, payload.arguments)
        relaunch = await self._watched(tool.name, response, payload.arguments)
        return SendAttempt(self._redaction.response(response), relaunch)

    async def _ready_for_a_call(self) -> None:
        # A resumed audit takes its tools from the checkpoint, never from list_tools.
        if self._original_names is None and self.redacting:
            await self.list_tools()
        if not self._control_ping_sent:
            await self._send_control_ping()

    async def _send_control_ping(self) -> None:
        self._watch.control_ping_answered(await self._client.ping())
        self._control_ping_sent = True

    async def _watched(
        self, tool_name: str, response: ToolResponse, arguments: dict[str, Any]
    ) -> Relaunch | None:
        step = self._watch.after_response(tool_name, response)
        if step is WatchStep.PING:
            step = self._watch.after_ping(tool_name, await self._client.ping())
        if step is not WatchStep.RELAUNCH:
            return None
        cause = self._watch.relaunch_cause()
        succeeded = await self._client.relaunch()
        self._watch.after_relaunch(tool_name, succeeded)
        if succeeded:
            await self._send_control_ping()
        return Relaunch(tool_name=tool_name, arguments=arguments, cause=cause, succeeded=succeeded)
