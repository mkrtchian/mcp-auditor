import json
from collections.abc import Sequence
from typing import Any, Literal

import httpx
import httpx2
import openai
import pytest
from langchain_anthropic.chat_models import AnthropicContextOverflowError
from langchain_core.exceptions import ContextOverflowError
from langchain_fireworks.chat_models import FireworksContextOverflowError
from langchain_google_genai.chat_models import GoogleContextOverflowError
from langchain_openai import ChatOpenAI
from langchain_openai.chat_models.base import (
    OpenAIAPIContextOverflowError,
    OpenAIContextOverflowError,
)
from openai.types.chat import ChatCompletion
from openai.types.chat.chat_completion import Choice
from openai.types.chat.chat_completion_message import ChatCompletionMessage
from openai.types.completion_usage import (
    CompletionTokensDetails,
    CompletionUsage,
    PromptTokensDetails,
)
from pydantic import BaseModel

from mcp_auditor.adapters.llm import (
    LLM,
    STRUCTURED_OUTPUTS,
    StructuredOutput,
)
from tests.fakes.chat_model import FakeChatModel, ScriptedResponse


class Output(BaseModel):
    value: str


PYDANTIC_SCHEMA = StructuredOutput(method="json_schema")
DICT_SCHEMA = StructuredOutput(method="json_schema", schema_as_dict=True)

A_FULL_USAGE = CompletionUsage(
    prompt_tokens=100,
    completion_tokens=50,
    total_tokens=150,
    prompt_tokens_details=PromptTokensDetails(cached_tokens=20),
    completion_tokens_details=CompletionTokensDetails(reasoning_tokens=10),
)


def an_llm(
    responses: Sequence[ScriptedResponse],
    schema: StructuredOutput = DICT_SCHEMA,
    max_parse_attempts: int = 3,
) -> LLM:
    return LLM(
        FakeChatModel(responses),  # pyrefly: ignore[bad-argument-type]
        schema,
        max_parse_attempts=max_parse_attempts,
    )


def an_llm_over(chat_model: FakeChatModel) -> LLM:
    return LLM(
        chat_model,  # pyrefly: ignore[bad-argument-type]
        DICT_SCHEMA,
        max_parse_attempts=3,
    )


_OVERFLOW_MESSAGE = "prompt is too long: 1200000 tokens > 1000000 maximum"
_OVERFLOW_REQUEST = httpx2.Request("POST", "https://provider.test/v1/messages")


def _a_400() -> httpx2.Response:
    return httpx2.Response(400, request=_OVERFLOW_REQUEST)


# Every ContextOverflowError subclass of the installed LangChain integrations, as each one
# raises it on its provider's overflow text.
CONTEXT_OVERFLOWS: dict[str, ContextOverflowError] = {
    "anthropic": AnthropicContextOverflowError(_OVERFLOW_MESSAGE, response=_a_400(), body=None),
    "openai": OpenAIContextOverflowError(_OVERFLOW_MESSAGE, response=_a_400(), body=None),
    "openai_api": OpenAIAPIContextOverflowError(_OVERFLOW_MESSAGE, _OVERFLOW_REQUEST, body=None),
    "google": GoogleContextOverflowError(
        400, {"error": {"message": _OVERFLOW_MESSAGE, "status": "INVALID_ARGUMENT"}}
    ),
    "fireworks": FireworksContextOverflowError(
        _OVERFLOW_MESSAGE,
        response=httpx.Response(400, request=httpx.Request("POST", "https://provider.test/v1")),
        body=None,
    ),
}


def token_details(cache_read: int, reasoning: int) -> dict[str, dict[str, int]]:
    return {
        "input_token_details": {"cache_read": cache_read},
        "output_token_details": {"reasoning": reasoning},
    }


def a_completion(
    finish_reason: Literal["length", "content_filter"],
    message: ChatCompletionMessage,
    usage: CompletionUsage | None,
) -> ChatCompletion:
    return ChatCompletion(
        id="scripted",
        created=0,
        model="scripted",
        object="chat.completion",
        choices=[Choice(index=0, finish_reason=finish_reason, message=message)],
        usage=usage,
    )


def a_cut_completion(usage: CompletionUsage | None) -> openai.LengthFinishReasonError:
    message = ChatCompletionMessage(role="assistant", content='{"value": "c')
    return openai.LengthFinishReasonError(completion=a_completion("length", message, usage))


async def the_openai_request_body(schema: type[BaseModel]) -> dict[str, Any]:
    # The recorded request is answered with a 400, which the SDK does not retry and the
    # adapter re-raises, so one call sends exactly one request.
    bodies: list[dict[str, Any]] = []

    def record(request: httpx2.Request) -> httpx2.Response:
        bodies.append(json.loads(request.content))
        error = {"message": "recorded", "type": "invalid_request_error"}
        return httpx2.Response(400, json={"error": error})

    chat_model = ChatOpenAI(
        model="gpt-6-luna",
        reasoning_effort="none",
        use_responses_api=True,
        max_retries=3,
        http_async_client=httpx2.AsyncClient(transport=httpx2.MockTransport(record)),
    )
    llm = LLM(chat_model, STRUCTURED_OUTPUTS["openai"], max_parse_attempts=3)
    with pytest.raises(openai.BadRequestError):
        await llm.generate_structured("prompt", schema)
    if len(bodies) != 1:
        raise AssertionError("expected one request")
    return bodies[0]
