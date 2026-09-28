import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel


@dataclass
class FakeAIMessage:
    usage_metadata: dict[str, Any]
    response_metadata: dict[str, Any] = field(default_factory=dict[str, Any])
    additional_kwargs: dict[str, Any] = field(default_factory=dict[str, Any])
    content: str | list[dict[str, Any]] = ""


class FakeChatModel:
    """Mimics BaseChatModel.with_structured_output(include_raw=True).

    Replays one scripted response per call. An exception in the script is raised.
    A throttled response first logs an HTTP 429 the way the provider SDK's client does.
    """

    def __init__(self, responses: Sequence["ScriptedResponse"]) -> None:
        self._responses = responses

    def with_structured_output(self, *_args: Any, **_kwargs: Any) -> "_FakeStructuredOutput":
        return _FakeStructuredOutput(self._responses)


@dataclass(frozen=True)
class Throttled:
    response: dict[str, Any]


type ScriptedResponse = dict[str, Any] | Exception | Throttled


class _FakeStructuredOutput:
    def __init__(self, responses: Sequence[ScriptedResponse]) -> None:
        self._responses = list(responses)
        self._call_index = 0

    async def ainvoke(self, _prompt: str) -> dict[str, Any]:
        response = self._responses[self._call_index]
        self._call_index += 1
        if isinstance(response, Exception):
            raise response
        if isinstance(response, Throttled):
            _log_throttled_request()
            return response.response
        return response


def _log_throttled_request() -> None:
    logging.getLogger("httpx2").info(
        'HTTP Request: %s %s "%s %d %s"',
        "POST",
        "https://provider.test/v1/responses",
        "HTTP/1.1",
        429,
        "Too Many Requests",
    )


def raw_response(
    parsed: BaseModel | dict[str, Any] | None,
    input_tokens: int,
    output_tokens: int,
    details: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    usage_metadata: dict[str, Any] = {"input_tokens": input_tokens, "output_tokens": output_tokens}
    return {
        "raw": FakeAIMessage(usage_metadata=usage_metadata | (details or {})),
        "parsed": parsed,
    }


def truncated(response: dict[str, Any], **marker: str) -> dict[str, Any]:
    response["raw"].response_metadata = marker
    return response
