import os
from dataclasses import dataclass
from typing import Any, Literal, NotRequired, TypedDict, cast

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel  # pyright: ignore[reportMissingTypeStubs]
from langchain_core.runnables import Runnable
from langchain_fireworks import ChatFireworks
from langchain_google_genai import ChatGoogleGenerativeAI  # pyright: ignore[reportMissingTypeStubs]
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, ValidationError

from mcp_auditor.config import Settings
from mcp_auditor.domain.models import TokenUsage
from mcp_auditor.domain.ports import UnparseableOutput


def create_llm(settings: Settings) -> "LLM":
    return _create_for_provider(settings, settings.resolve_model())


def create_judge_llm(settings: Settings) -> "LLM":
    return _create_for_provider(settings, settings.resolve_judge_model())


def _create_for_provider(settings: Settings, model: str) -> "LLM":
    chat_model = make_chat_model(settings, model)
    return LLM(chat_model, _STRUCTURED_OUTPUT[settings.provider], max_parse_attempts=3)


@dataclass(frozen=True)
class StructuredOutput:
    method: Literal["json_schema", "function_calling"]
    schema_as_dict: bool = False


# OpenAI gets a dict: langchain-openai makes a Pydantic class strict, and strict mode
# rejects the open object AuditPayload.arguments.
_STRUCTURED_OUTPUT = {
    "google": StructuredOutput(method="json_schema"),
    "anthropic": StructuredOutput(method="function_calling"),
    "openai": StructuredOutput(method="json_schema", schema_as_dict=True),
    "fireworks": StructuredOutput(method="json_schema"),
}


def make_chat_model(settings: Settings, model: str) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    reasoning = settings.resolve_reasoning(model)
    if settings.provider == "anthropic":
        return _make_anthropic_model(model)
    if settings.provider == "google":
        return _make_google_model(model, reasoning)
    if settings.provider == "openai":
        return _make_openai_model(model, reasoning)
    if settings.provider == "fireworks":
        return _make_fireworks_model(model, reasoning)
    raise ValueError(
        f"Unknown provider: {settings.provider!r}. "
        "Use 'google', 'anthropic', 'openai' or 'fireworks'."
    )


def _make_anthropic_model(model: str) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    return ChatAnthropic(model=model, max_retries=3)  # type: ignore[arg-type]


def _make_google_model(model: str, reasoning: str | None) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    if reasoning is None:
        return ChatGoogleGenerativeAI(model=model, max_retries=3)  # pyright: ignore[reportUnknownArgumentType]
    return ChatGoogleGenerativeAI(model=model, thinking_level=reasoning, max_retries=3)  # pyright: ignore[reportUnknownArgumentType,reportArgumentType]


def _make_openai_model(model: str, reasoning: str | None) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    # ChatOpenAI raises openai.OpenAIError on a missing key, which the CLI does not catch.
    if not os.environ.get("OPENAI_API_KEY"):
        raise ValueError("OPENAI_API_KEY is not set.")
    if reasoning is None:
        return ChatOpenAI(model=model, use_responses_api=True, max_retries=3)
    return ChatOpenAI(
        model=model, reasoning_effort=reasoning, use_responses_api=True, max_retries=3
    )


def _make_fireworks_model(model: str, reasoning: str | None) -> BaseChatModel:  # pyright: ignore[reportMissingTypeStubs]
    if reasoning is None:
        return ChatFireworks(model=model, max_retries=3)
    return ChatFireworks(model=model, reasoning_effort=reasoning, max_retries=3)


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
    def __init__(
        self,
        model: BaseChatModel,  # pyright: ignore[reportMissingTypeStubs]
        structured_output: StructuredOutput,
        max_parse_attempts: int,
    ):
        self._model = model
        self._structured_output = structured_output
        self._max_parse_attempts = max_parse_attempts

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, TokenUsage]:
        structured = self._bind(output_schema)
        accumulated_usage = TokenUsage()
        for _attempt in range(self._max_parse_attempts):
            raw_response = await structured.ainvoke(prompt)
            parsed, usage = self._unpack_raw_response(raw_response)
            accumulated_usage = accumulated_usage.add(usage)
            output = _validated(parsed, output_schema)
            if output is not None:
                return output, accumulated_usage
        raise UnparseableOutput(
            f"LLM returned unparseable output after {self._max_parse_attempts} attempts"
        )

    def _bind(self, output_schema: type[BaseModel]) -> Runnable[str, object]:
        method = self._structured_output.method
        if self._structured_output.schema_as_dict:
            return self._model.with_structured_output(  # pyright: ignore[reportUnknownMemberType]
                output_schema.model_json_schema(), method=method, strict=False, include_raw=True
            )
        return self._model.with_structured_output(  # pyright: ignore[reportUnknownMemberType]
            output_schema, method=method, include_raw=True
        )

    def _unpack_raw_response(
        self,
        raw_response: object,
    ) -> tuple[object, TokenUsage]:
        """Langchain's include_raw=True returns {"raw": AIMessage, "parsed": BaseModel}.

        Single coupling point with that contract.
        """
        response = cast(dict[str, Any], raw_response)
        metadata: _UsageMetadata | None = response["raw"].usage_metadata
        usage = _to_token_usage(metadata)
        return response["parsed"], usage


def _validated[T: BaseModel](parsed: object, output_schema: type[T]) -> T | None:
    if parsed is None or isinstance(parsed, output_schema):
        return parsed
    try:
        return output_schema.model_validate(parsed)
    except ValidationError:
        return None


def _to_token_usage(metadata: _UsageMetadata | None) -> TokenUsage:
    if metadata is None:
        return TokenUsage()
    return TokenUsage(
        input_tokens=metadata["input_tokens"],
        output_tokens=metadata["output_tokens"],
        cached_input_tokens=metadata.get("input_token_details", {}).get("cache_read", 0),
        reasoning_tokens=metadata.get("output_token_details", {}).get("reasoning", 0),
    )
