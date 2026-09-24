# pyright: reportArgumentType=false
from dataclasses import dataclass
from typing import Any

import pytest
from pydantic import BaseModel

from mcp_auditor.adapters.llm import LLM, make_chat_model
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import TokenUsage


class _DummyOutput(BaseModel):
    value: str


@dataclass
class _FakeAIMessage:
    usage_metadata: dict[str, Any]


def _raw_response(
    parsed: BaseModel | None,
    input_tokens: int,
    output_tokens: int,
    details: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    usage_metadata: dict[str, Any] = {"input_tokens": input_tokens, "output_tokens": output_tokens}
    return {
        "raw": _FakeAIMessage(usage_metadata=usage_metadata | (details or {})),
        "parsed": parsed,
    }


def _details(cache_read: int, reasoning: int) -> dict[str, dict[str, int]]:
    return {
        "input_token_details": {"cache_read": cache_read},
        "output_token_details": {"reasoning": reasoning},
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
            _raw_response(None, 100, 50, _details(cache_read=30, reasoning=10)),
            _raw_response(_DummyOutput(value="ok"), 100, 50, _details(cache_read=20, reasoning=5)),
        ]
        llm = LLM(_FakeModel(responses), max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage == TokenUsage(
            input_tokens=200, output_tokens=100, cached_input_tokens=50, reasoning_tokens=15
        )

    @pytest.mark.asyncio
    async def test_single_successful_attempt_returns_exact_usage(self):
        responses = [
            _raw_response(parsed=_DummyOutput(value="ok"), input_tokens=100, output_tokens=50),
        ]
        llm = LLM(_FakeModel(responses), max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage == TokenUsage(input_tokens=100, output_tokens=50)


class TestTokenDetails:
    @pytest.mark.asyncio
    async def test_details_fill_cached_input_and_reasoning_tokens(self):
        responses = [
            _raw_response(_DummyOutput(value="ok"), 100, 50, _details(cache_read=40, reasoning=20)),
        ]
        llm = LLM(_FakeModel(responses), max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage.cached_input_tokens == 40
        assert usage.reasoning_tokens == 20

    @pytest.mark.asyncio
    async def test_metadata_without_details_leaves_them_at_zero(self):
        responses = [_raw_response(_DummyOutput(value="ok"), 100, 50)]
        llm = LLM(_FakeModel(responses), max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage.cached_input_tokens == 0
        assert usage.reasoning_tokens == 0


class TestMakeChatModel:
    def test_google_default_model_gets_minimal_thinking(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("GOOGLE_API_KEY", "dummy")
        settings = Settings(provider="google", model="", judge_model="", reasoning="")

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "model", None) == "gemini-3.1-flash-lite"
        assert getattr(chat_model, "thinking_level", None) == "minimal"

    def test_google_judge_override_gets_no_thinking_level(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("GOOGLE_API_KEY", "dummy")
        settings = Settings(
            provider="google", model="", judge_model="gemini-3.1-pro-preview", reasoning=""
        )

        chat_model = make_chat_model(settings, settings.resolve_judge_model())

        assert getattr(chat_model, "model", None) == "gemini-3.1-pro-preview"
        assert getattr(chat_model, "thinking_level", "unset") is None

    def test_anthropic_builds_the_named_model(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
        settings = Settings(provider="anthropic", model="", judge_model="", reasoning="")

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "model", None) == "claude-haiku-4-5-20251001"
