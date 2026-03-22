from typing import Any, TypedDict, cast

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel  # pyright: ignore[reportMissingTypeStubs]
from langchain_google_genai import ChatGoogleGenerativeAI  # pyright: ignore[reportMissingTypeStubs]
from pydantic import BaseModel

from mcp_auditor.config import Settings
from mcp_auditor.domain.models import TokenUsage


class _UsageMetadata(TypedDict):
    input_tokens: int
    output_tokens: int


def create_llm(settings: Settings) -> "AnthropicLLM | GoogleLLM":
    return _create_for_provider(settings.provider, settings.resolve_model())


def create_judge_llm(settings: Settings) -> "AnthropicLLM | GoogleLLM":
    return _create_for_provider(settings.provider, settings.resolve_judge_model())


def _create_for_provider(provider: str, model: str) -> "AnthropicLLM | GoogleLLM":
    if provider == "anthropic":
        return AnthropicLLM(model=model)
    if provider == "google":
        return GoogleLLM(model=model)
    raise ValueError(f"Unknown provider: {provider!r}. Use 'google' or 'anthropic'.")


class _BaseLLM:
    def __init__(self, model: BaseChatModel, max_retries: int):  # pyright: ignore[reportMissingTypeStubs]
        self._model = model
        self._max_retries = max_retries

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, TokenUsage]:
        structured = self._model.with_structured_output(  # pyright: ignore[reportUnknownVariableType,reportUnknownMemberType]
            output_schema, include_raw=True
        )
        for _attempt in range(self._max_retries):
            raw_response = await structured.ainvoke(prompt)  # pyright: ignore[reportUnknownVariableType]
            parsed, usage = self._unpack_raw_response(cast(object, raw_response))
            if parsed is not None:
                return cast(T, parsed), usage
        raise ValueError(f"LLM returned unparseable output after {self._max_retries} attempts")

    def _unpack_raw_response(
        self,
        raw_response: object,
    ) -> tuple[BaseModel | None, TokenUsage]:
        """Langchain's include_raw=True returns {"raw": AIMessage, "parsed": BaseModel}.

        Single coupling point with that contract.
        """
        response = cast(dict[str, Any], raw_response)
        metadata: _UsageMetadata | None = response["raw"].usage_metadata
        usage = _to_token_usage(metadata)
        return response["parsed"], usage


def _to_token_usage(metadata: _UsageMetadata | None) -> TokenUsage:
    if metadata is None:
        return TokenUsage()
    return TokenUsage(
        input_tokens=metadata["input_tokens"],
        output_tokens=metadata["output_tokens"],
    )


class AnthropicLLM(_BaseLLM):
    def __init__(self, model: str, max_retries: int = 3):
        super().__init__(
            model=ChatAnthropic(model=model, max_retries=max_retries),  # type: ignore[arg-type]
            max_retries=max_retries,
        )


class GoogleLLM(_BaseLLM):
    def __init__(self, model: str, max_retries: int = 3):
        super().__init__(
            model=ChatGoogleGenerativeAI(model=model),  # pyright: ignore[reportUnknownArgumentType]
            max_retries=max_retries,
        )
