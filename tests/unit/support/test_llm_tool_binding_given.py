from typing import Any

import anthropic
import httpx2
from langchain_anthropic import ChatAnthropic
from pydantic import BaseModel

from mcp_auditor.adapters.llm import LLM, StructuredOutput


class Finding(BaseModel):
    value: str


def an_llm_answering(body: dict[str, Any], thinking: str = "adaptive") -> LLM:
    return an_llm_on(a_chat_model_answering(body, thinking), schema_as_dict=False)


def an_llm_on(chat_model: ChatAnthropic, schema_as_dict: bool) -> LLM:
    structured_output = StructuredOutput(method="tool_binding", schema_as_dict=schema_as_dict)
    return LLM(chat_model, structured_output, max_parse_attempts=3)


def a_chat_model_answering(body: dict[str, Any], thinking: str = "adaptive") -> ChatAnthropic:
    chat_model = ChatAnthropic(  # pyright: ignore[reportCallIssue]
        model="claude-haiku-5-5",  # pyright: ignore[reportCallIssue]
        api_key="dummy",
        thinking={"type": thinking},
        effort="low",
        max_retries=0,
    )
    # ChatAnthropic takes no HTTP client: its async client is a cached_property, so the
    # instance's cached value is seeded with one whose transport replays the body.
    replay = httpx2.MockTransport(lambda _request: httpx2.Response(200, json=body))
    http_client = httpx2.AsyncClient(transport=replay)
    vars(chat_model)["_async_client"] = anthropic.AsyncClient(
        api_key="dummy", http_client=http_client
    )
    return chat_model


def a_tool_use_answer(input_tokens: int, output_tokens: int) -> dict[str, Any]:
    tool_use = {"type": "tool_use", "id": "toolu_1", "name": "Finding", "input": {"value": "ok"}}
    return _message([_thinking_block(), tool_use], "tool_use", input_tokens, output_tokens)


def a_refusal() -> dict[str, Any]:
    text = {"type": "text", "text": "I can't help with that."}
    stop_details = {"type": "refusal", "category": "cyber", "explanation": None}
    return _message([text], "refusal", 100, 10) | {"stop_details": stop_details}


def a_cut_during_thinking() -> dict[str, Any]:
    return _message([_thinking_block()], "max_tokens", 100, 8192)


def a_thinking_only_answer() -> dict[str, Any]:
    return _message([_thinking_block()], "end_turn", 100, 50)


def _thinking_block() -> dict[str, Any]:
    return {"type": "thinking", "thinking": "Considering the tool.", "signature": "sig"}


def _message(
    content: list[dict[str, Any]], stop_reason: str, input_tokens: int, output_tokens: int
) -> dict[str, Any]:
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-haiku-5-5",
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "stop_details": None,
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
    }
