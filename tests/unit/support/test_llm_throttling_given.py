from collections.abc import Callable
from typing import Any

import anthropic
import httpx
import httpx2
import openai
from google.genai.errors import ClientError
from langchain_google_genai.chat_models import GoogleRateLimitError

_URL = "https://provider.test/v1/chat/completions"

type RateLimitBuilder = Callable[..., Exception]


def an_openai_rate_limit(
    headers: dict[str, str] | None = None, body: dict[str, Any] | None = None
) -> openai.RateLimitError:
    response = httpx2.Response(429, headers=headers, request=httpx2.Request("POST", _URL))
    return openai.RateLimitError("Error code: 429 - slow down", response=response, body=body)


def an_anthropic_rate_limit(headers: dict[str, str] | None = None) -> anthropic.RateLimitError:
    response = httpx2.Response(429, headers=headers, request=httpx2.Request("POST", _URL))
    return anthropic.RateLimitError("Error code: 429 - slow down", response=response, body=None)


def an_openai_server_error() -> openai.InternalServerError:
    response = httpx2.Response(500, request=httpx2.Request("POST", _URL))
    return openai.InternalServerError("Error code: 500", response=response, body=None)


def a_google_rate_limit(headers: dict[str, str]) -> GoogleRateLimitError:
    response = httpx.Response(429, headers=headers, request=httpx.Request("POST", _URL))
    cause = ClientError(429, {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED"}}, response)
    try:
        raise GoogleRateLimitError("Error calling model 'gemini' (RESOURCE_EXHAUSTED)") from cause
    except GoogleRateLimitError as error:
        return error
