import os
from typing import Any, TypedDict, cast

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel  # pyright: ignore[reportMissingTypeStubs]
from langchain_google_genai import ChatGoogleGenerativeAI  # pyright: ignore[reportMissingTypeStubs]
from pydantic import BaseModel

from mcp_auditor.domain.models import TokenUsage


class _UsageMetadata(TypedDict):
    input_tokens: int
    output_tokens: int


def create_llm() -> "AnthropicLLM | GoogleLLM":
    """Pick the LLM adapter based on the MCP_AUDITOR_PROVIDER env var.

    Defaults to "google". Set to "anthropic" to use Claude.
    """
    provider = os.environ.get("MCP_AUDITOR_PROVIDER", "google").lower()
    if provider == "anthropic":
        return AnthropicLLM()
    if provider == "google":
        return GoogleLLM()
    raise ValueError(f"Unknown LLM provider: {provider!r}. Use 'google' or 'anthropic'.")


class _BaseLLM:
    """Shared logic for LangChain-based LLM adapters."""

    def __init__(self, model: BaseChatModel, max_retries: int):  # pyright: ignore[reportMissingTypeStubs]
        self._model = model
        self._max_retries = max_retries
        self._usage = TokenUsage()

    @property
    def usage_stats(self) -> TokenUsage:
        return self._usage

    async def generate_structured[T: BaseModel](self, prompt: str, output_schema: type[T]) -> T:
        structured = self._model.with_structured_output(  # pyright: ignore[reportUnknownVariableType,reportUnknownMemberType]
            output_schema, include_raw=True
        )
        for _attempt in range(self._max_retries):
            raw_response = await structured.ainvoke(prompt)  # pyright: ignore[reportUnknownVariableType]
            parsed, usage = self._unpack_raw_response(cast(object, raw_response))
            self._accumulate_usage(usage)
            if parsed is not None:
                return cast(T, parsed)
        raise ValueError(f"LLM returned unparseable output after {self._max_retries} attempts")

    def _unpack_raw_response(
        self,
        raw_response: object,
    ) -> tuple[BaseModel | None, _UsageMetadata | None]:
        """Langchain's include_raw=True returns {"raw": AIMessage, "parsed": BaseModel}.

        Single coupling point with that contract.
        """
        response = cast(dict[str, Any], raw_response)
        return response["parsed"], response["raw"].usage_metadata

    def _accumulate_usage(self, metadata: _UsageMetadata | None) -> None:
        if metadata:
            self._usage = self._usage.add(
                TokenUsage(
                    input_tokens=metadata["input_tokens"],
                    output_tokens=metadata["output_tokens"],
                )
            )


class AnthropicLLM(_BaseLLM):
    def __init__(self, model: str = "claude-haiku-4-5-20251001", max_retries: int = 3):
        super().__init__(
            model=ChatAnthropic(model=model, max_retries=max_retries),  # type: ignore[arg-type]
            max_retries=max_retries,
        )


class GoogleLLM(_BaseLLM):
    def __init__(self, model: str = "gemini-3.1-flash-lite-preview", max_retries: int = 3):
        super().__init__(
            model=ChatGoogleGenerativeAI(model=model),  # pyright: ignore[reportUnknownArgumentType]
            max_retries=max_retries,
        )
