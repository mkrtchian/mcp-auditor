from typing import Any

import httpx
import httpx2
from fireworks import AsyncFireworks
from langchain_fireworks import ChatFireworks
from langchain_google_genai import ChatGoogleGenerativeAI  # pyright: ignore[reportMissingTypeStubs]
from pydantic import SecretStr

_URL = "https://provider.test/v1/chat/completions"

_CHAT_COMPLETION: dict[str, Any] = {
    "id": "completion-1",
    "object": "chat.completion",
    "created": 0,
    "model": "test-model",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
    ],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}

_GENERATE_CONTENT: dict[str, Any] = {
    "candidates": [
        {"content": {"role": "model", "parts": [{"text": "ok"}]}, "finishReason": "STOP"}
    ],
    "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2},
}


def an_httpx_client_answering(statuses: list[int]) -> httpx.AsyncClient:
    statuses_left = iter(statuses)

    def respond(_request: httpx.Request) -> httpx.Response:
        status = next(statuses_left)
        return httpx.Response(status, json=_CHAT_COMPLETION if status == 200 else {})

    return httpx.AsyncClient(transport=httpx.MockTransport(respond))


def an_httpx2_client_answering(statuses: list[int]) -> httpx2.AsyncClient:
    statuses_left = iter(statuses)

    def respond(_request: httpx2.Request) -> httpx2.Response:
        status = next(statuses_left)
        return httpx2.Response(status, json=_CHAT_COMPLETION if status == 200 else {})

    return httpx2.AsyncClient(transport=httpx2.MockTransport(respond))


async def calls(client: httpx.AsyncClient | httpx2.AsyncClient, count: int) -> None:
    for _ in range(count):
        await client.post(_URL)


def a_fireworks_model_answering(statuses: list[int]) -> ChatFireworks:
    sdk_client = AsyncFireworks(
        api_key="test",
        base_url="https://provider.test/v1",
        max_retries=0,
        http_client=an_httpx_client_answering(statuses),
    )
    return ChatFireworks(
        api_key=SecretStr("test"),
        model="test-model",
        max_retries=3,
        async_client=sdk_client.chat.completions,
    )


def a_google_model_answering(statuses: list[int]) -> ChatGoogleGenerativeAI:
    statuses_left = iter(statuses)

    def respond(_request: httpx.Request) -> httpx.Response:
        status = next(statuses_left)
        return httpx.Response(status, json=_GENERATE_CONTENT if status == 200 else {})

    return ChatGoogleGenerativeAI(  # pyright: ignore[reportUnknownVariableType]
        model="test-model",
        google_api_key=SecretStr("test"),
        max_retries=3,
        client_args={"transport": httpx.MockTransport(respond)},
    )


async def no_wait(_seconds: float) -> None:
    """Stands in for asyncio.sleep, which tenacity's async retry awaits between attempts."""
