import json
from typing import Any

import httpx2
from langchain_anthropic import ChatAnthropic

from mcp_auditor.adapters.llm import LLM, StructuredOutput
from tests.unit.auditor.support.anthropic_request_bodies import an_anthropic_chat_model_on


def an_llm_answering(body: dict[str, Any]) -> LLM:
    return LLM(_chat_model_answering(body), StructuredOutput(method="anthropic_json_schema"))


def _chat_model_answering(body: dict[str, Any]) -> ChatAnthropic:
    return an_anthropic_chat_model_on(
        httpx2.MockTransport(lambda _request: httpx2.Response(200, json=body))
    )


def a_wire_payload(category: str, description: str, arguments: object) -> dict[str, Any]:
    return {"category": category, "description": description, "arguments": json.dumps(arguments)}


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
