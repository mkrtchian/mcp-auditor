from typing import Any, Protocol

from pydantic import BaseModel

from mcp_auditor.domain.models import TokenUsage, ToolDefinition, ToolResponse


class MCPClientPort(Protocol):
    """Port for interacting with an MCP server.

    Lifecycle (connect/disconnect) is managed by the adapter via an async
    context manager. The port only exposes business operations.
    """

    async def list_tools(self) -> list[ToolDefinition]: ...
    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse: ...


class LLMPort(Protocol):
    async def generate_structured[T: BaseModel](self, prompt: str, output_schema: type[T]) -> T: ...

    @property
    def usage_stats(self) -> TokenUsage: ...
