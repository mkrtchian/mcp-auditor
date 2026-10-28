"""The auditor's patience with a throttled model provider, on top of the clients' own retries.

A retryable HTTP 429 is waited on, honouring the provider's hint, until a bound per model
call. Once one call of an audit has exhausted its patience, the breaker of that audit makes
every later call of it fail at once: the provider has not served it within the bound.
"""

import asyncio
import random
from collections.abc import Awaitable, Callable, Generator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import cast

from langchain_core.exceptions import ModelRateLimitError

_TOO_MANY_REQUESTS = 429
_PAYMENT_REQUIRED = 402
# Billing limits, some raised as rate-limit errors although waiting cannot cure them: OpenAI's
# quota type, Anthropic's billing type (its 402), and their codes.
_BILLING_TYPES = frozenset({"insufficient_quota", "billing_error"})
_BILLING_CODES = frozenset(
    {
        "credit_balance_exhausted",
        "organization_spend_limit_exceeded",
        "project_spend_limit_exceeded",
        "organization_usage_limit_exceeded",
        "insufficient_quota",
        # Anthropic's tier spend cap, a 429 with no retry hint.
        "enforced_spend_limit_reached",
    }
)
# Anthropic answers a spend limit the organization set, and a credit balance run dry, with a
# plain 400 `invalid_request_error` that only its message tells apart.
_BILLING_MESSAGES = (
    "You have reached your specified API usage limits",
    "You have reached your specified workspace API usage limits",
    "credit balance is too low",
)


@dataclass(frozen=True)
class Throttle:
    retry_after: float | None


def throttle_of(error: Exception) -> Throttle | None:
    if not _is_rate_limit(error):
        return None
    if is_billing_limit(error):
        return None
    headers = _response_headers(error)
    if headers.get("x-should-retry") == "false":
        return None
    return Throttle(retry_after=_retry_hint(headers))


def _is_rate_limit(error: Exception) -> bool:
    return (
        isinstance(error, ModelRateLimitError)
        or getattr(error, "status_code", None) == _TOO_MANY_REQUESTS
    )


def is_billing_limit(error: BaseException) -> bool:
    body = _error_body(error)
    message = body.get("message")
    return (
        _named_in(getattr(error, "type", None), _BILLING_TYPES)
        or _named_in(getattr(error, "code", None), _BILLING_CODES)
        or getattr(error, "status_code", None) == _PAYMENT_REQUIRED
        or _named_in(_detail_code(body), _BILLING_CODES)
        or (isinstance(message, str) and any(text in message for text in _BILLING_MESSAGES))
    )


def _named_in(value: object, names: frozenset[str]) -> bool:
    # Read on any error out of an audit, whose `code` may be unhashable.
    return isinstance(value, str) and value in names


def _error_body(error: BaseException) -> dict[str, object]:
    # OpenAI's SDK keeps the error object as the body, Anthropic's the whole response.
    body: object = getattr(error, "body", None)
    if not isinstance(body, dict):
        return {}
    response = cast(dict[str, object], body)
    inner = response.get("error", response)
    return cast(dict[str, object], inner) if isinstance(inner, dict) else {}


def _detail_code(body: dict[str, object]) -> object:
    details = body.get("details")
    return cast(dict[str, object], details).get("error_code") if isinstance(details, dict) else None


def _response_headers(error: Exception) -> dict[str, str]:
    # GoogleRateLimitError carries no response, the google-genai error it is raised from does.
    response = getattr(error, "response", None) or getattr(error.__cause__, "response", None)
    headers = getattr(response, "headers", None)
    if headers is None:
        return {}
    return {str(name).lower(): str(value) for name, value in headers.items()}


def _retry_hint(headers: dict[str, str]) -> float | None:
    milliseconds = _number(headers.get("retry-after-ms"))
    if milliseconds is not None:
        return milliseconds / 1000
    # A Retry-After given as an HTTP date reads as no hint.
    return _number(headers.get("retry-after"))


def _number(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


@dataclass(frozen=True)
class ThrottlePatience:
    max_total_wait: float = 300.0
    first_delay: float = 10.0
    max_delay: float = 60.0
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    jitter: Callable[[], float] = random.random

    def next_delay(self, retry: int, hint: float | None) -> float:
        if hint is None:
            base = min(self.first_delay * 2**retry, self.max_delay)
        else:
            # A hint of 0 floored, else the wait would never reach the bound.
            base = max(hint, 1.0)
        # Spread upward only: concurrent calls do not retry together, a hint is never undercut.
        return base * (1 + 0.25 * self.jitter())

    def exhausted(self, waited: float, delay: float) -> bool:
        return waited + delay > self.max_total_wait


@dataclass
class ThrottleBreaker:
    tripped_by: str | None = None

    def trip(self, provider_message: str) -> None:
        if self.tripped_by is None:
            self.tripped_by = provider_message


# Holds a mutable breaker that a trip mutates, never re-sets: LangGraph's nodes and gathered
# tasks run in copies of the context, which map the variable to the same breaker.
_current_breaker: ContextVar[ThrottleBreaker | None] = ContextVar("_current_breaker", default=None)


@contextmanager
def one_audit() -> Generator[ThrottleBreaker]:
    breaker = ThrottleBreaker()
    token = _current_breaker.set(breaker)
    try:
        yield breaker
    finally:
        _current_breaker.reset(token)


def current_breaker() -> ThrottleBreaker | None:
    return _current_breaker.get()
