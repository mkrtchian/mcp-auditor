from typing import Any

from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.config import load_settings
from mcp_auditor.domain.models import ToolDefinition, ToolResponse
from mcp_auditor.domain.ports import MCPClientPort
from mcp_auditor.graph.builder import build_graph


def create_graph():
    """Factory for LangGraph Studio."""
    settings = load_settings()
    llm = create_llm(settings)
    judge_llm = create_judge_llm(settings)
    return build_graph(llm, mcp_client=_placeholder_mcp_client(), judge_llm=judge_llm)


def _studio_mcp_not_available(operation: str) -> NotImplementedError:
    return NotImplementedError(
        f"MCP {operation} requires a running server. Use the CLI: mcp-auditor run"
    )


class _StudioMCPPlaceholder:
    """Placeholder for Studio — MCP operations require the CLI."""

    async def list_tools(self) -> list[ToolDefinition]:
        raise _studio_mcp_not_available("tool discovery")

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        raise _studio_mcp_not_available("tool execution")


def _placeholder_mcp_client() -> MCPClientPort:
    return _StudioMCPPlaceholder()  # type: ignore[return-value]
