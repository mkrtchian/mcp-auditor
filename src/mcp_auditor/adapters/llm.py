from dataclasses import dataclass
from typing import Any, Literal, NotRequired, TypedDict, cast

from langchain_core.language_models import BaseChatModel  # pyright: ignore[reportMissingTypeStubs]
from langchain_core.runnables import Runnable
from pydantic import BaseModel, ValidationError

from mcp_auditor.adapters.chat_model_factory import make_chat_model
from mcp_auditor.adapters.llm_refusals import refusal_from_error, refusal_from_metadata
from mcp_auditor.adapters.llm_tool_binding import bind_schema_as_tool
from mcp_auditor.adapters.throttling import counting_throttles, install_throttle_log_handler
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.ports import ProviderRefusal, UnparseableOutput


def create_llm(settings: Settings) -> "LLM":
    return _create_for_provider(settings, settings.resolve_model())


def create_judge_llm(settings: Settings) -> "LLM":
    return _create_for_provider(settings, settings.resolve_judge_model())


def _create_for_provider(settings: Settings, model: str) -> "LLM":
    install_throttle_log_handler()
    chat_model = make_chat_model(settings, model)
    return LLM(chat_model, _STRUCTURED_OUTPUT[settings.provider], max_parse_attempts=3)


@dataclass(frozen=True)
class StructuredOutput:
    method: Literal["json_schema", "function_calling", "tool_binding"]
    schema_as_dict: bool = False


# OpenAI and Alibaba, both through ChatOpenAI, get a dict: ChatOpenAI makes a Pydantic
# class strict, and strict mode rejects the open object AuditPayload.arguments.
# Anthropic binds the schema as a tool itself, so an answer without the tool call (a
# refusal, a cut during thinking) still reaches the refusal and truncation checks.
_STRUCTURED_OUTPUT = {
    "google": StructuredOutput(method="json_schema"),
    "anthropic": StructuredOutput(method="tool_binding"),
    "openai": StructuredOutput(method="json_schema", schema_as_dict=True),
    "fireworks": StructuredOutput(method="json_schema"),
    "alibaba": StructuredOutput(method="json_schema", schema_as_dict=True),
}


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
    ) -> tuple[T, ProviderUsage]:
        structured = self._bind(output_schema)
        accumulated_usage = ProviderUsage()
        truncated_attempts = 0
        for _attempt in range(self._max_parse_attempts):
            raw_response, throttled_requests = await _invoke(structured, prompt, accumulated_usage)
            attempt = self._unpack_raw_response(raw_response, throttled_requests)
            accumulated_usage = accumulated_usage.add(attempt.usage)
            if attempt.refusal is not None:
                raise ProviderRefusal(attempt.refusal, accumulated_usage)
            if attempt.truncated:
                truncated_attempts += 1
                continue
            output = _validated(attempt.parsed, output_schema)
            if output is not None:
                return output, accumulated_usage
        raise UnparseableOutput(self._max_parse_attempts, truncated_attempts, accumulated_usage)

    def _bind(self, output_schema: type[BaseModel]) -> Runnable[str, object]:
        method = self._structured_output.method
        if method == "tool_binding":
            return bind_schema_as_tool(
                self._model, output_schema, self._structured_output.schema_as_dict
            )
        if self._structured_output.schema_as_dict:
            return self._model.with_structured_output(  # pyright: ignore[reportUnknownMemberType]
                output_schema.model_json_schema(), method=method, strict=False, include_raw=True
            )
        return self._model.with_structured_output(  # pyright: ignore[reportUnknownMemberType]
            output_schema, method=method, include_raw=True
        )

    def _unpack_raw_response(self, raw_response: object, throttled_requests: int) -> "_Attempt":
        """Langchain's include_raw=True returns {"raw": AIMessage, "parsed": BaseModel}.

        Single coupling point with that contract.
        """
        response = cast(dict[str, Any], raw_response)
        raw_message = response["raw"]
        metadata: _UsageMetadata | None = raw_message.usage_metadata
        return _Attempt(
            parsed=response["parsed"],
            usage=_to_provider_usage(metadata, throttled_requests),
            truncated=_was_truncated(raw_message.response_metadata),
            refusal=refusal_from_metadata(raw_message),
        )


@dataclass(frozen=True)
class _Attempt:
    parsed: object
    usage: ProviderUsage
    truncated: bool
    refusal: str | None


async def _invoke(
    structured: Runnable[str, object], prompt: str, usage_so_far: ProviderUsage
) -> tuple[object, int]:
    with counting_throttles() as tally:
        try:
            raw_response = await structured.ainvoke(prompt)
        except Exception as error:
            refusal = refusal_from_error(error)
            if refusal is None:
                raise
            usage = usage_so_far.add(ProviderUsage(throttled_requests=tally.requests))
            raise ProviderRefusal(refusal, usage) from error
    return raw_response, tally.requests


def _was_truncated(response_metadata: dict[str, Any]) -> bool:
    # LangChain repairs a JSON cut by the output cap, so a truncated answer would pass as valid.
    return (
        response_metadata.get("status") == "incomplete"
        or response_metadata.get("finish_reason") == "length"
        or response_metadata.get("stop_reason") == "max_tokens"
    )


def _validated[T: BaseModel](parsed: object, output_schema: type[T]) -> T | None:
    if parsed is None or isinstance(parsed, output_schema):
        return parsed
    try:
        return output_schema.model_validate(parsed)
    except ValidationError:
        return None


def _to_provider_usage(metadata: _UsageMetadata | None, throttled_requests: int) -> ProviderUsage:
    if metadata is None:
        return ProviderUsage(throttled_requests=throttled_requests)
    return ProviderUsage(
        input_tokens=metadata["input_tokens"],
        output_tokens=metadata["output_tokens"],
        cached_input_tokens=metadata.get("input_token_details", {}).get("cache_read", 0),
        reasoning_tokens=metadata.get("output_token_details", {}).get("reasoning", 0),
        throttled_requests=throttled_requests,
    )
