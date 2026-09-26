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
    """

    def __init__(self, responses: list[dict[str, Any] | Exception]) -> None:
        self._responses = responses

    def with_structured_output(self, *_args: Any, **_kwargs: Any) -> "_FakeStructuredOutput":
        return _FakeStructuredOutput(self._responses)


class _FakeStructuredOutput:
    def __init__(self, responses: list[dict[str, Any] | Exception]) -> None:
        self._responses = list(responses)
        self._call_index = 0

    async def ainvoke(self, _prompt: str) -> dict[str, Any]:
        response = self._responses[self._call_index]
        self._call_index += 1
        if isinstance(response, Exception):
            raise response
        return response


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
