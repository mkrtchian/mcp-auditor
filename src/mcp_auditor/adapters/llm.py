import logging
from dataclasses import dataclass, field
from typing import Any, Literal, NotRequired, TypedDict, cast

import openai
from langchain_core.language_models import BaseChatModel  # pyright: ignore[reportMissingTypeStubs]
from langchain_core.runnables import Runnable
from openai.types.completion_usage import CompletionUsage
from pydantic import BaseModel, ValidationError

from mcp_auditor.adapters.anthropic_structured_output import bind_anthropic_json_schema
from mcp_auditor.adapters.chat_model_factory import make_chat_model
from mcp_auditor.adapters.llm_refusals import refusal_from_error, refusal_from_metadata
from mcp_auditor.adapters.llm_throttling import (
    Throttle,
    ThrottlePatience,
    current_breaker,
    throttle_of,
)
from mcp_auditor.adapters.openrouter_models import OpenRouterEffortCatalog
from mcp_auditor.adapters.throttling import counting_throttles, install_throttle_log_handler
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import Judgment, ProviderUsage
from mcp_auditor.domain.ports import ProviderRefusal, ProviderThrottled, UnparseableOutput

# Shared so the generator and the judge on one model fetch OpenRouter's listing once.
_PROCESS_EFFORTS = OpenRouterEffortCatalog()
_DEFAULT_PATIENCE = ThrottlePatience()
_THROTTLING_LOGGER = logging.getLogger("mcp_auditor.throttling")


def create_llm(
    settings: Settings,
    efforts: OpenRouterEffortCatalog = _PROCESS_EFFORTS,
    patience: ThrottlePatience = _DEFAULT_PATIENCE,
) -> "LLM":
    return _create_for_provider(settings, _ModelChoice(settings.resolve_model(), patience), efforts)


def create_judge_llm(
    settings: Settings,
    efforts: OpenRouterEffortCatalog = _PROCESS_EFFORTS,
    patience: ThrottlePatience = _DEFAULT_PATIENCE,
) -> "LLM":
    choice = _ModelChoice(settings.resolve_judge_model(), patience)
    return _create_for_provider(settings, choice, efforts)


@dataclass(frozen=True)
class _ModelChoice:
    model: str
    patience: ThrottlePatience


def _create_for_provider(
    settings: Settings, choice: _ModelChoice, efforts: OpenRouterEffortCatalog
) -> "LLM":
    install_throttle_log_handler()
    chat_model = make_chat_model(settings, choice.model, efforts)
    structured_output = _STRUCTURED_OUTPUT[settings.provider]
    return LLM(chat_model, structured_output, max_parse_attempts=3, patience=choice.patience)


@dataclass(frozen=True)
class StructuredOutput:
    method: Literal["json_schema", "function_calling", "anthropic_json_schema"]
    schema_as_dict: bool = False
    strict_schemas: frozenset[type[BaseModel]] = frozenset()


# OpenAI, Alibaba and OpenRouter, all through ChatOpenAI, get a dict, and strict is an explicit
# opt-in per schema and per provider. A Pydantic class goes strict through the OpenAI SDK with
# the open object AuditPayload.arguments left open, which the API refuses. A dict bound strictly
# has that object closed by langchain, so every payload would come back empty with no error
# (langchain also makes every property required). Strict is granted only to a schema with no
# open object and no optional field.
# Anthropic uses its native structured output, forced even with thinking on. The open
# arguments object is carried as a JSON string on that path and decoded back in the adapter
# (anthropic_structured_output); an answer with no valid structured output (a refusal, a cut
# during thinking, a non-JSON arguments string) still reaches the refusal and truncation checks.
_STRUCTURED_OUTPUT = {
    "google": StructuredOutput(method="json_schema"),
    "anthropic": StructuredOutput(method="anthropic_json_schema"),
    "openai": StructuredOutput(
        method="json_schema", schema_as_dict=True, strict_schemas=frozenset({Judgment})
    ),
    "fireworks": StructuredOutput(method="json_schema"),
    "alibaba": StructuredOutput(method="json_schema", schema_as_dict=True),
    "openrouter": StructuredOutput(method="json_schema", schema_as_dict=True),
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
        patience: ThrottlePatience = _DEFAULT_PATIENCE,
    ):
        self._model = model
        self._structured_output = structured_output
        self._max_parse_attempts = max_parse_attempts
        self._patience = patience

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]:
        structured = self._bind(output_schema)
        state = _CallState()
        truncated_attempts = 0
        for _attempt in range(self._max_parse_attempts):
            attempt = await self._attempt(structured, prompt, state)
            state.usage = state.usage.add(attempt.usage)
            if attempt.refusal is not None:
                raise ProviderRefusal(attempt.refusal, state.usage)
            if attempt.truncated:
                truncated_attempts += 1
                continue
            output = _validated(attempt.parsed, output_schema)
            if output is not None:
                return output, state.usage
        raise UnparseableOutput(self._max_parse_attempts, truncated_attempts, state.usage)

    def _bind(self, output_schema: type[BaseModel]) -> Runnable[str, object]:
        method = self._structured_output.method
        if method == "anthropic_json_schema":
            return bind_anthropic_json_schema(self._model, output_schema)
        if self._structured_output.schema_as_dict:
            return self._model.with_structured_output(  # pyright: ignore[reportUnknownMemberType]
                output_schema.model_json_schema(),
                method=method,
                strict=output_schema in self._structured_output.strict_schemas,
                include_raw=True,
            )
        return self._model.with_structured_output(  # pyright: ignore[reportUnknownMemberType]
            output_schema, method=method, include_raw=True
        )

    async def _attempt(
        self, structured: Runnable[str, object], prompt: str, state: "_CallState"
    ) -> "_Attempt":
        # The 429s of the throttled iterations go straight into the call's usage, so they
        # survive whatever ends the call: an answer, a cut, a refusal or ProviderThrottled.
        while True:
            _refuse_if_breaker_tripped(state)
            outcome = await self._call_once(structured, prompt, state.usage)
            if isinstance(outcome, _Attempt):
                return outcome
            state.usage = state.usage.add(ProviderUsage(throttled_requests=outcome.requests))
            await self._wait_out(outcome, state)

    async def _wait_out(self, throttled: "_Throttled", state: "_CallState") -> None:
        delay = self._patience.next_delay(state.retries, throttled.throttle.retry_after)
        if self._patience.exhausted(state.waited, delay):
            breaker = current_breaker()
            if breaker is not None:
                breaker.trip(throttled.provider_message)
            raise ProviderThrottled(
                throttled.provider_message, state.waited, state.usage
            ) from throttled.error
        _THROTTLING_LOGGER.warning(
            f"the model provider is throttling requests, waiting {delay:.0f} s "
            f"(retry {state.retries + 1})"
        )
        await self._patience.sleep(delay)
        state.waited += delay
        state.retries += 1

    async def _call_once(
        self, structured: Runnable[str, object], prompt: str, usage_so_far: ProviderUsage
    ) -> "_Attempt | _Throttled":
        with counting_throttles() as tally:
            try:
                raw_response = await structured.ainvoke(prompt)
            except openai.LengthFinishReasonError as error:
                # The SDK's parse path raises on a cut answer before any message exists.
                usage = _completion_usage(error.completion.usage, tally.requests)
                return _Attempt(parsed=None, usage=usage, truncated=True, refusal=None)
            except Exception as error:
                throttle = throttle_of(error)
                if throttle is not None:
                    return _Throttled(throttle, str(error), tally.requests, error)
                refusal = refusal_from_error(error)
                if refusal is None:
                    raise
                usage = usage_so_far.add(_refused_usage(error, tally.requests))
                raise ProviderRefusal(refusal, usage) from error
        return self._unpack_raw_response(raw_response, tally.requests)

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


@dataclass
class _CallState:
    usage: ProviderUsage = field(default_factory=ProviderUsage)
    waited: float = 0.0
    retries: int = 0


@dataclass(frozen=True)
class _Attempt:
    parsed: object
    usage: ProviderUsage
    truncated: bool
    refusal: str | None


@dataclass(frozen=True)
class _Throttled:
    throttle: Throttle
    provider_message: str
    requests: int
    error: Exception


def _refuse_if_breaker_tripped(state: _CallState) -> None:
    breaker = current_breaker()
    if breaker is not None and breaker.tripped_by is not None:
        raise ProviderThrottled(
            "not sent, an earlier call of this audit was throttled past every retry: "
            f"{breaker.tripped_by}",
            state.waited,
            state.usage,
        )


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
        largest_input_tokens=metadata["input_tokens"],
    )


def _refused_usage(error: Exception, throttled_requests: int) -> ProviderUsage:
    # A content_filter finish is raised as an error, yet its completion carries the billed tokens.
    if isinstance(error, openai.ContentFilterFinishReasonError) and error.completion is not None:
        return _completion_usage(error.completion.usage, throttled_requests)
    return ProviderUsage(throttled_requests=throttled_requests)


def _completion_usage(usage: CompletionUsage | None, throttled_requests: int) -> ProviderUsage:
    if usage is None:
        return ProviderUsage(throttled_requests=throttled_requests)
    prompt_details = usage.prompt_tokens_details
    completion_details = usage.completion_tokens_details
    return ProviderUsage(
        input_tokens=usage.prompt_tokens,
        output_tokens=usage.completion_tokens,
        cached_input_tokens=(prompt_details and prompt_details.cached_tokens) or 0,
        reasoning_tokens=(completion_details and completion_details.reasoning_tokens) or 0,
        throttled_requests=throttled_requests,
        largest_input_tokens=usage.prompt_tokens,
    )
