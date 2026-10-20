from typing import Any

import httpx2
import openai
from openai.types.chat.chat_completion_message import ChatCompletionMessage
from openai.types.completion_usage import CompletionUsage

from tests.unit.support.test_llm_adapter_given import (
    A_FULL_USAGE,
    Output,
    a_completion,
    an_llm,
)

__all__ = ["A_FULL_USAGE", "Output", "an_llm"]

OPENAI_POLICY_MESSAGE = (
    "Invalid prompt: your prompt was flagged as potentially violating our usage policy."
)


def a_bad_request(message: str, code: str | None) -> openai.BadRequestError:
    request = httpx2.Request("POST", "https://api.example.test/v1/responses")
    response = httpx2.Response(400, request=request)
    body = {"message": message, "type": "invalid_request_error", "code": code}
    return openai.BadRequestError(f"Error code: 400 - {body}", response=response, body=body)


def a_permission_denied(body: dict[str, Any]) -> openai.PermissionDeniedError:
    request = httpx2.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
    response = httpx2.Response(403, request=request)
    return openai.PermissionDeniedError(f"Error code: 403 - {body}", response=response, body=body)


def a_content_filtered(
    refusal: str | None, usage: CompletionUsage | None = None
) -> openai.ContentFilterFinishReasonError:
    message = ChatCompletionMessage(role="assistant", content=None, refusal=refusal)
    completion = a_completion("content_filter", message, usage)
    return openai.ContentFilterFinishReasonError(completion=completion)


def wrapped(cause: Exception) -> Exception:
    try:
        raise RuntimeError("wrapper") from cause
    except RuntimeError as wrapper:
        return wrapper


def with_raw(response: dict[str, Any], **raw_fields: Any) -> dict[str, Any]:
    for name, value in raw_fields.items():
        setattr(response["raw"], name, value)
    return response
