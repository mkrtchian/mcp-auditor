import json
from typing import Any

import httpx2
import openai
import pytest
from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from mcp_auditor.adapters.llm import LLM, STRUCTURED_OUTPUTS


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
