from typing import Any, Protocol

from pydantic import BaseModel

from mcp_auditor.domain.models import ProviderUsage, ToolDefinition, ToolResponse


class MCPClientPort(Protocol):
    """The adapter opens the first session and closes the last one. `relaunch` ends the server
    and opens another session on a new one. Neither `ping` nor `relaunch` raises.
    """

    async def list_tools(self) -> list[ToolDefinition]: ...
    async def call_tool(self, name: str, args: dict[str, Any]) -> ToolResponse: ...
    async def ping(self) -> bool:
        """True on any response, an error response included."""
        ...

    async def relaunch(self) -> bool: ...


class UnparseableOutput(ValueError):
    """The model answered, but no attempt matched the requested schema."""

    def __init__(self, attempts: int, truncated_attempts: int, usage: ProviderUsage):
        super().__init__(f"LLM returned unparseable output after {attempts} attempts")
        self.attempts = attempts
        self.truncated_attempts = truncated_attempts
        self.usage = usage


class ProviderRefusal(Exception):
    """The provider refused the request or its answer on policy grounds,
    before or instead of a model answer.
    """

    def __init__(self, provider_message: str, usage: ProviderUsage):
        super().__init__(provider_message)
        self.provider_message = provider_message
        self.usage = usage


class ProviderThrottled(Exception):
    def __init__(self, provider_message: str, waited_seconds: float, usage: ProviderUsage):
        super().__init__(
            "the model provider throttled the request past every retry"
            f" ({waited_seconds:.0f} s waited by the auditor): {provider_message}"
        )
        self.provider_message = provider_message
        self.waited_seconds = waited_seconds
        self.usage = usage


class PromptTooLong(Exception):
    """The provider rejected the prompt as longer than the model's context window."""

    def __init__(self, usage: ProviderUsage):
        super().__init__(
            "the model provider rejected the prompt as longer than the model's context window"
        )
        self.usage = usage


class LLMPort(Protocol):
    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]: ...
