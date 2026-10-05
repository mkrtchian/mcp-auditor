"""Counts the HTTP 429 responses the model provider sends back, per LLM call.

The provider clients retry a throttled request by themselves, so the one place every 429
shows is the response line their HTTP client logs: `openai` and `alibaba` log on the
`httpx2` logger, `anthropic` and `fireworks` on the `httpx` logger, and Google's model is
given an `httpx` transport because `google-genai` would otherwise go through `aiohttp`,
which logs nothing. The count reads that log format, so a library that changes it
silently stops the count, which the tests on real `httpx` and `httpx2` clients pin.
"""

import logging
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

_HTTP_LOGGERS = ("httpx", "httpx2")
_TOO_MANY_REQUESTS = 429


@dataclass
class ThrottleTally:
    requests: int = 0


_current_tally: ContextVar[ThrottleTally | None] = ContextVar("_current_tally", default=None)


@contextmanager
def counting_throttles() -> Generator[ThrottleTally]:
    """Counts the HTTP 429 responses received while the block runs, in this task only."""
    tally = ThrottleTally()
    token = _current_tally.set(tally)
    try:
        yield tally
    finally:
        _current_tally.reset(token)


def install_throttle_log_handler() -> None:
    for name in _HTTP_LOGGERS:
        logger = logging.getLogger(name)
        if not any(isinstance(handler, _ThrottleLogHandler) for handler in logger.handlers):
            logger.addHandler(_ThrottleLogHandler())
        if logger.getEffectiveLevel() > logging.INFO:
            logger.setLevel(logging.INFO)


class _ThrottleLogHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        tally = _current_tally.get()
        if tally is not None and _is_throttled_response(record):
            tally.requests += 1


def _is_throttled_response(record: logging.LogRecord) -> bool:
    arguments = record.args
    return (
        isinstance(record.msg, str)
        and record.msg.startswith("HTTP Request:")
        and isinstance(arguments, tuple)
        and len(arguments) >= 4
        and arguments[3] == _TOO_MANY_REQUESTS
    )
