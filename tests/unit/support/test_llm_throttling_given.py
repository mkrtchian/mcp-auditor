from collections.abc import Callable
from typing import Any

import anthropic
import httpx
import httpx2
import openai
from google.genai.errors import ClientError
from langchain_anthropic.chat_models import AnthropicInvalidRequestError, AnthropicRateLimitError
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


def an_anthropic_billing_error() -> anthropic.APIStatusError:
    """A 402 `billing_error`, which the SDK raises as a plain `APIStatusError`."""
    body = _anthropic_body("billing_error", "There is an issue with your billing")
    return anthropic.APIStatusError("Error code: 402", response=_response(402), body=body)


def an_anthropic_spend_limit_reached() -> AnthropicInvalidRequestError:
    """A spend limit the organization set, answered as a 400 `invalid_request_error`."""
    message = (
        "You have reached your specified API usage limits."
        " You will regain access on 2026-11-01 at 00:00 UTC."
    )
    body = _anthropic_body("invalid_request_error", message)
    return AnthropicInvalidRequestError(
        message="Error code: 400", response=_response(400), body=body
    )


def an_anthropic_workspace_spend_limit_reached() -> AnthropicInvalidRequestError:
    message = "You have reached your specified workspace API usage limits."
    body = _anthropic_body("invalid_request_error", message)
    return AnthropicInvalidRequestError(
        message="Error code: 400", response=_response(400), body=body
    )


def an_anthropic_credit_balance_too_low() -> AnthropicInvalidRequestError:
    message = (
        "Your credit balance is too low to access the Anthropic API."
        " Please go to Plans & Billing to upgrade or purchase credits."
    )
    body = _anthropic_body("invalid_request_error", message)
    return AnthropicInvalidRequestError(
        message="Error code: 400", response=_response(400), body=body
    )


def an_anthropic_spend_cap_reached() -> AnthropicRateLimitError:
    """The tier's monthly spend cap, answered as a 429 with no retry hint."""
    body = _anthropic_body(
        "rate_limit_error",
        "You have reached your API usage limits.",
        details={"error_code": "enforced_spend_limit_reached"},
    )
    return AnthropicRateLimitError(message="Error code: 429", response=_response(429), body=body)


def an_anthropic_invalid_request() -> AnthropicInvalidRequestError:
    body = _anthropic_body("invalid_request_error", "max_tokens: field required")
    return AnthropicInvalidRequestError(
        message="Error code: 400", response=_response(400), body=body
    )


def _anthropic_body(
    error_type: str, message: str, details: dict[str, str] | None = None
) -> dict[str, Any]:
    error: dict[str, Any] = {"type": error_type, "message": message}
    if details is not None:
        error["details"] = details
    return {"type": "error", "error": error, "request_id": "req_test"}


def _response(status: int) -> httpx2.Response:
    return httpx2.Response(status, request=httpx2.Request("POST", _URL))
