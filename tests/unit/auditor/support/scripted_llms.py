from collections.abc import Sequence
from typing import Literal

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


DICT_SCHEMA = StructuredOutput(method="json_schema", schema_as_dict=True)

A_FULL_USAGE = CompletionUsage(
    prompt_tokens=100,
    completion_tokens=50,
    total_tokens=150,
    prompt_tokens_details=PromptTokensDetails(cached_tokens=20),
    completion_tokens_details=CompletionTokensDetails(reasoning_tokens=10),
)


def an_llm(responses: Sequence[ScriptedResponse], schema: StructuredOutput = DICT_SCHEMA) -> LLM:
    return LLM(FakeChatModel(responses), schema)  # pyrefly: ignore[bad-argument-type]


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
