from typing import Any

from mcp_auditor.domain import ToolDefinition, ToolResponse


class FakeMCPClient:
    def __init__(
        self,
        tools: list[ToolDefinition],
        responses: dict[str, ToolResponse] | None = None,
    ):
        self._tools = tools
        self._responses = responses or {}

    async def list_tools(self) -> list[ToolDefinition]:
        return self._tools

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        if name in self._responses:
            return self._responses[name]
        return ToolResponse(content="ok")
