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
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self) -> list[ToolDefinition]:
        return self._tools

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        self.calls.append((name, args))
        if name in self._responses:
            return self._responses[name]
        return ToolResponse(content="ok")
