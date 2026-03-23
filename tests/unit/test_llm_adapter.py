# pyright: reportArgumentType=false
from dataclasses import dataclass
from typing import Any

import pytest
from pydantic import BaseModel

from mcp_auditor.adapters.llm import LLM
from mcp_auditor.domain.models import TokenUsage


class _DummyOutput(BaseModel):
    value: str


@dataclass
class _FakeAIMessage:
    usage_metadata: dict[str, int]


def _raw_response(
    parsed: BaseModel | None, input_tokens: int, output_tokens: int
) -> dict[str, Any]:
    return {
        "raw": _FakeAIMessage(
            usage_metadata={"input_tokens": input_tokens, "output_tokens": output_tokens}
        ),
        "parsed": parsed,
    }


class _FakeStructuredOutput:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self._responses = list(responses)
        self._call_index = 0

    async def ainvoke(self, _prompt: str) -> dict[str, Any]:
        response = self._responses[self._call_index]
        self._call_index += 1
        return response


class _FakeModel:
    """Fake that mimics BaseChatModel.with_structured_output(include_raw=True)."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self._responses = responses

    def with_structured_output(self, *_args: Any, **_kwargs: Any) -> _FakeStructuredOutput:
        return _FakeStructuredOutput(self._responses)


class TestTokenAccumulationOnRetry:
    @pytest.mark.asyncio
    async def test_usage_reflects_all_attempts_not_just_successful_one(self):
        responses = [
            _raw_response(parsed=None, input_tokens=100, output_tokens=50),
            _raw_response(parsed=_DummyOutput(value="ok"), input_tokens=100, output_tokens=50),
        ]
        llm = LLM(_FakeModel(responses), max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage == TokenUsage(input_tokens=200, output_tokens=100)

    @pytest.mark.asyncio
    async def test_single_successful_attempt_returns_exact_usage(self):
        responses = [
            _raw_response(parsed=_DummyOutput(value="ok"), input_tokens=100, output_tokens=50),
        ]
        llm = LLM(_FakeModel(responses), max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage == TokenUsage(input_tokens=100, output_tokens=50)
