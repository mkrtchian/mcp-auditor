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

from langchain_core.exceptions import ModelRateLimitError

_TOO_MANY_REQUESTS = 429
# OpenAI's "no credit left", raised as a rate-limit error although waiting cannot cure it.
_NO_CREDIT_CODE = "insufficient_quota"


@dataclass(frozen=True)
class Throttle:
    retry_after: float | None


def throttle_of(error: Exception) -> Throttle | None:
    if not _is_rate_limit(error):
        return None
    if getattr(error, "code", None) == _NO_CREDIT_CODE:
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
