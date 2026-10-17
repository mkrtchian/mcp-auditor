import json
from typing import Any

import anthropic
import httpx2
from langchain_anthropic import ChatAnthropic

from mcp_auditor.adapters.llm import LLM, StructuredOutput


def an_llm_answering(body: dict[str, Any], thinking: str = "adaptive") -> LLM:
    return an_llm_on(a_chat_model_answering(body, thinking))


def an_llm_on(chat_model: ChatAnthropic) -> LLM:
    structured_output = StructuredOutput(method="anthropic_json_schema")
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


def a_json_schema_answer(
    document: dict[str, Any], input_tokens: int, output_tokens: int
) -> dict[str, Any]:
    # On the json_schema path langchain parses the raw message's text blocks; the thinking
    # block is skipped. The JSON document matches the bound wire schema, so arguments arrives
    # as a JSON-encoded string (double escaping in the wire body is intended).
    text = {"type": "text", "text": json.dumps(document)}
    return _message([_thinking_block(), text], "end_turn", input_tokens, output_tokens)


def a_refusal() -> dict[str, Any]:
    text = {"type": "text", "text": "I can't help with that."}
    stop_details = {"type": "refusal", "category": "cyber", "explanation": None}
    return _message([text], "refusal", 100, 10) | {"stop_details": stop_details}


def a_cut_during_thinking() -> dict[str, Any]:
    return _message([_thinking_block()], "max_tokens", 100, 8192)


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
