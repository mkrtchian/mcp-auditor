from collections.abc import Sequence
from typing import Literal

import openai
from openai.types.chat import ChatCompletion
from openai.types.chat.chat_completion import Choice
from openai.types.chat.chat_completion_message import ChatCompletionMessage
from openai.types.completion_usage import (
    CompletionTokensDetails,
    CompletionUsage,
    PromptTokensDetails,
)
from pydantic import BaseModel

from mcp_auditor.adapters.llm import LLM, StructuredOutput
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
        FakeChatModel(responses),  # pyright: ignore[reportArgumentType]
        schema,
        max_parse_attempts=max_parse_attempts,
    )


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
