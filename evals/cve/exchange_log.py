"""A client decorator that keeps each tool call and its response, shared by the calibration check
and the replay.

The calibration check grades what the server returned, so a target out of calibration can be
post-mortemed from the exchanges (which call swallowed the proof, or what the benign call
surfaced). The replay reads the kept calls back to send them, in order, against the patched
server. A call never raises through it: `StdioMCPClient.call_tool` turns every exception into an
error `ToolResponse`, so the kept sequence holds exactly the calls the audit sent.
"""

from typing import Any

from mcp_auditor.domain.models import ToolDefinition, ToolResponse
from mcp_auditor.domain.ports import MCPClientPort

type Exchange = tuple[str, dict[str, Any], ToolResponse]


class ExchangeLog:
    def __init__(self, inner: MCPClientPort) -> None:
        self._inner = inner
        self.exchanges: list[Exchange] = []

    async def list_tools(self) -> list[ToolDefinition]:
        return await self._inner.list_tools()

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        response = await self._inner.call_tool(name, args)
        self.exchanges.append((name, args, response))
        return response
