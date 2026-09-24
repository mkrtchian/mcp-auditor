from typing import Any, NotRequired, TypedDict, cast

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel  # pyright: ignore[reportMissingTypeStubs]
from langchain_google_genai import ChatGoogleGenerativeAI  # pyright: ignore[reportMissingTypeStubs]
from pydantic import BaseModel

from mcp_auditor.config import Settings
from mcp_auditor.domain.models import TokenUsage


def create_llm(settings: Settings) -> "LLM":
    return _create_for_provider(settings, settings.resolve_model())


def create_judge_llm(settings: Settings) -> "LLM":
    return _create_for_provider(settings, settings.resolve_judge_model())


def _create_for_provider(settings: Settings, model: str) -> "LLM":
    return LLM(make_chat_model(settings, model), max_parse_attempts=3)


def make_chat_model(settings: Settings, model: str) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    reasoning = settings.resolve_reasoning(model)
    if settings.provider == "anthropic":
        return _make_anthropic_model(model)
    if settings.provider == "google":
        return _make_google_model(model, reasoning)
    raise ValueError(f"Unknown provider: {settings.provider!r}. Use 'google' or 'anthropic'.")


def _make_anthropic_model(model: str) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    return ChatAnthropic(model=model, max_retries=3)  # type: ignore[arg-type]


def _make_google_model(model: str, reasoning: str | None) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    if reasoning is None:
        return ChatGoogleGenerativeAI(model=model, max_retries=3)  # pyright: ignore[reportUnknownArgumentType]
    return ChatGoogleGenerativeAI(model=model, thinking_level=reasoning, max_retries=3)  # pyright: ignore[reportUnknownArgumentType,reportArgumentType]


class _InputTokenDetails(TypedDict):
    cache_read: NotRequired[int]


class _OutputTokenDetails(TypedDict):
    reasoning: NotRequired[int]


class _UsageMetadata(TypedDict):
    input_tokens: int
    output_tokens: int
    input_token_details: NotRequired[_InputTokenDetails]
    output_token_details: NotRequired[_OutputTokenDetails]


class LLM:
    def __init__(self, model: BaseChatModel, max_parse_attempts: int):  # pyright: ignore[reportMissingTypeStubs]
        self._model = model
        self._max_parse_attempts = max_parse_attempts

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, TokenUsage]:
        structured = self._model.with_structured_output(  # pyright: ignore[reportUnknownVariableType,reportUnknownMemberType]
            output_schema, include_raw=True
        )
        accumulated_usage = TokenUsage()
        for _attempt in range(self._max_parse_attempts):
            raw_response = await structured.ainvoke(prompt)  # pyright: ignore[reportUnknownVariableType]
            parsed, usage = self._unpack_raw_response(cast(object, raw_response))
            accumulated_usage = accumulated_usage.add(usage)
            if parsed is not None:
                return cast(T, parsed), accumulated_usage
        raise ValueError(
            f"LLM returned unparseable output after {self._max_parse_attempts} attempts"
        )

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
        cached_input_tokens=metadata.get("input_token_details", {}).get("cache_read", 0),
        reasoning_tokens=metadata.get("output_token_details", {}).get("reasoning", 0),
    )
