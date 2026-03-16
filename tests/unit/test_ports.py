"""Structural typing checks for domain ports.

These tests verify that classes implementing the Protocol interfaces
are accepted by the type checker. They run at test time but the real
value is in the pyright check during CI.
"""

from typing import Any

from pydantic import BaseModel

from mcp_auditor.domain import LLMPort, MCPClientPort, TokenUsage, ToolDefinition, ToolResponse


class FakeMCPClient:
    async def list_tools(self) -> list[ToolDefinition]:
        return []

    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse:
        return ToolResponse(content="ok")


class FakeLLM:
    async def generate_structured[T: BaseModel](self, prompt: str, output_schema: type[T]) -> T:
        return output_schema.model_validate({})

    @property
    def usage_stats(self) -> TokenUsage:
        return TokenUsage()


def test_fake_mcp_client_satisfies_port() -> None:
    client: MCPClientPort = FakeMCPClient()
    assert client is not None


def test_fake_llm_satisfies_port() -> None:
    llm: LLMPort = FakeLLM()
    assert llm is not None
