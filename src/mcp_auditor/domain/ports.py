from typing import Any, ClassVar, Protocol, override

from pydantic import BaseModel

from mcp_auditor.domain.model_calls import MissedCallCause
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


class ModelCallMissed(Exception):
    """Raised for a missed model call, with the usage the call spent before it gave up."""

    cause: ClassVar[MissedCallCause]

    def __init__(self, message: str, usage: ProviderUsage):
        super().__init__(message)
        self.usage = usage

    @property
    def detail(self) -> str:
        return str(self)


class UnreadableAnswer(ModelCallMissed, ValueError):
    """The model answered, but no attempt matched the requested schema."""

    cause = MissedCallCause.UNREADABLE_ANSWER

    def __init__(self, parse_attempts: int, truncated_parse_attempts: int, usage: ProviderUsage):
        super().__init__(f"LLM returned unparseable output after {parse_attempts} attempts", usage)
        self.parse_attempts = parse_attempts
        self.truncated_parse_attempts = truncated_parse_attempts

    @property
    @override
    def detail(self) -> str:
        return (
            f"no answer matched the expected format after {self.parse_attempts} attempts"
            f" ({self.truncated_parse_attempts} cut at the output limit)"
        )


class ProviderRefusal(ModelCallMissed):
    """The provider refused the request or its answer on policy grounds,
    before or instead of a model answer.
    """

    cause = MissedCallCause.PROVIDER_REFUSAL

    def __init__(self, provider_message: str, usage: ProviderUsage):
        super().__init__(provider_message, usage)
        self.provider_message = provider_message


class ProviderThrottled(ModelCallMissed):
    cause = MissedCallCause.PROVIDER_THROTTLED

    def __init__(self, provider_message: str, waited_seconds: float, usage: ProviderUsage):
        super().__init__(
            "the model provider throttled the request past every retry"
            f" ({waited_seconds:.0f} s waited by the auditor): {provider_message}",
            usage,
        )
        self.provider_message = provider_message
        self.waited_seconds = waited_seconds


class PromptTooLong(ModelCallMissed):
    cause = MissedCallCause.PROMPT_TOO_LONG

    def __init__(self, usage: ProviderUsage):
        super().__init__(
            "the model provider rejected the prompt as longer than the model's context window",
            usage,
        )


class LLMPort(Protocol):
    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]: ...
