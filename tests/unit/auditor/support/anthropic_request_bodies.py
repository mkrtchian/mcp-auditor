import json
from typing import Any

import anthropic
import httpx2
import pytest
from langchain_anthropic import ChatAnthropic
from pydantic import BaseModel

from mcp_auditor.adapters.llm import LLM, STRUCTURED_OUTPUTS


async def the_anthropic_request_body(schema: type[BaseModel]) -> dict[str, Any]:
    # The recorded request is answered with a 400, which the adapter re-raises, and the client
    # does not retry, so one call sends exactly one request.
    bodies: list[dict[str, Any]] = []

    def record(request: httpx2.Request) -> httpx2.Response:
        bodies.append(json.loads(request.content))
        error = {"type": "invalid_request_error", "message": "recorded"}
        return httpx2.Response(400, json={"type": "error", "error": error})

    chat_model = an_anthropic_chat_model_on(httpx2.MockTransport(record))
    llm = LLM(chat_model, STRUCTURED_OUTPUTS["anthropic"])
    with pytest.raises(anthropic.BadRequestError):
        await llm.generate_structured("prompt", schema)
    if len(bodies) != 1:
        raise AssertionError("expected one request")
    return bodies[0]


def an_anthropic_chat_model_on(transport: httpx2.MockTransport) -> ChatAnthropic:
    chat_model = ChatAnthropic(
        model="claude-haiku-5-5",
        api_key="dummy",
        thinking={"type": "adaptive"},
        effort="low",
        max_retries=0,
    )
    # ChatAnthropic takes no HTTP client: its async client is a cached_property, so the
    # instance's cached value is seeded with one on the given transport. It carries an explicit
    # timeout, as the production client does: on the default one the SDK refuses a
    # non-streaming call whose max_tokens could outlast 10 minutes.
    http_client = httpx2.AsyncClient(transport=transport)
    vars(chat_model)["_async_client"] = anthropic.AsyncClient(
        api_key="dummy", http_client=http_client, timeout=120
    )
    return chat_model
