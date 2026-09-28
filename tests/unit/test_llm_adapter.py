# pyright: reportArgumentType=false
import pytest
from pydantic import BaseModel

from mcp_auditor.adapters.llm import LLM, StructuredOutput, make_chat_model
from mcp_auditor.adapters.throttling import install_throttle_log_handler
from mcp_auditor.config import Settings
from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.ports import UnparseableOutput
from tests.fakes.chat_model import FakeChatModel, Throttled, raw_response, truncated


class _DummyOutput(BaseModel):
    value: str


_PYDANTIC_SCHEMA = StructuredOutput(method="json_schema")
_DICT_SCHEMA = StructuredOutput(method="json_schema", schema_as_dict=True)


def _details(cache_read: int, reasoning: int) -> dict[str, dict[str, int]]:
    return {
        "input_token_details": {"cache_read": cache_read},
        "output_token_details": {"reasoning": reasoning},
    }


class TestTokenAccumulationOnRetry:
    @pytest.mark.asyncio
    async def test_usage_reflects_all_attempts_not_just_successful_one(self):
        responses = [
            raw_response(None, 100, 50, _details(cache_read=30, reasoning=10)),
            raw_response(_DummyOutput(value="ok"), 100, 50, _details(cache_read=20, reasoning=5)),
        ]
        llm = LLM(FakeChatModel(responses), _PYDANTIC_SCHEMA, max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage == ProviderUsage(
            input_tokens=200, output_tokens=100, cached_input_tokens=50, reasoning_tokens=15
        )

    @pytest.mark.asyncio
    async def test_single_successful_attempt_returns_exact_usage(self):
        responses = [
            raw_response(parsed=_DummyOutput(value="ok"), input_tokens=100, output_tokens=50),
        ]
        llm = LLM(FakeChatModel(responses), _PYDANTIC_SCHEMA, max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage == ProviderUsage(input_tokens=100, output_tokens=50)


class TestTokenDetails:
    @pytest.mark.asyncio
    async def test_details_fill_cached_input_and_reasoning_tokens(self):
        responses = [
            raw_response(_DummyOutput(value="ok"), 100, 50, _details(cache_read=40, reasoning=20)),
        ]
        llm = LLM(FakeChatModel(responses), _PYDANTIC_SCHEMA, max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage.cached_input_tokens == 40
        assert usage.reasoning_tokens == 20

    @pytest.mark.asyncio
    async def test_metadata_without_details_leaves_them_at_zero(self):
        responses = [raw_response(_DummyOutput(value="ok"), 100, 50)]
        llm = LLM(FakeChatModel(responses), _PYDANTIC_SCHEMA, max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage.cached_input_tokens == 0
        assert usage.reasoning_tokens == 0


class TestDictSchema:
    @pytest.mark.asyncio
    async def test_a_dict_matching_the_schema_is_returned_as_the_model(self):
        responses = [raw_response({"value": "ok"}, 100, 50)]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        output, _ = await llm.generate_structured("prompt", _DummyOutput)

        assert output == _DummyOutput(value="ok")

    @pytest.mark.asyncio
    async def test_a_dict_failing_validation_is_retried_with_its_usage_counted(self):
        responses = [
            raw_response({"unexpected": 1}, 100, 50),
            raw_response({"value": "ok"}, 100, 50),
        ]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        output, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert output == _DummyOutput(value="ok")
        assert usage == ProviderUsage(input_tokens=200, output_tokens=100)

    @pytest.mark.asyncio
    async def test_dicts_failing_validation_on_every_attempt_raise(self):
        responses = [raw_response({"unexpected": 1}, 100, 50) for _ in range(3)]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(UnparseableOutput, match="unparseable output after 3 attempts"):
            await llm.generate_structured("prompt", _DummyOutput)

    @pytest.mark.asyncio
    async def test_the_raised_error_carries_the_usage_of_every_attempt(self):
        responses = [raw_response({"unexpected": 1}, 100, 50 + attempt) for attempt in range(3)]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(UnparseableOutput) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.usage == ProviderUsage(input_tokens=300, output_tokens=153)
        assert raised.value.truncated_attempts == 0


class TestTruncatedOutput:
    @pytest.mark.asyncio
    async def test_an_incomplete_response_is_retried(self):
        responses = [
            truncated(raw_response(_DummyOutput(value="cut"), 100, 4096), status="incomplete"),
            raw_response(_DummyOutput(value="ok"), 100, 50),
        ]
        llm = LLM(FakeChatModel(responses), _PYDANTIC_SCHEMA, max_parse_attempts=3)

        output, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert output == _DummyOutput(value="ok")
        assert usage == ProviderUsage(input_tokens=200, output_tokens=4146)

    @pytest.mark.asyncio
    async def test_a_response_cut_at_the_length_limit_on_every_attempt_raises(self):
        responses = [
            truncated(raw_response({"value": "cut"}, 100, 4096), finish_reason="length")
            for _ in range(2)
        ]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=2)

        with pytest.raises(UnparseableOutput):
            await llm.generate_structured("prompt", _DummyOutput)

    @pytest.mark.asyncio
    async def test_the_raised_error_counts_the_truncated_attempts_and_their_usage(self):
        responses = [
            truncated(raw_response({"value": "cut"}, 100, 8192), finish_reason="length")
            for _ in range(2)
        ]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=2)

        with pytest.raises(UnparseableOutput) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.truncated_attempts == 2
        assert raised.value.usage == ProviderUsage(input_tokens=200, output_tokens=16384)

    @pytest.mark.asyncio
    async def test_a_truncated_attempt_among_malformed_ones_is_counted_alone(self):
        responses = [
            truncated(raw_response({"value": "cut"}, 100, 8192), finish_reason="length"),
            raw_response({"unexpected": 1}, 100, 50),
            raw_response({"unexpected": 1}, 100, 50),
        ]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(UnparseableOutput) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.truncated_attempts == 1


class TestThrottledRequests:
    @pytest.mark.asyncio
    async def test_a_throttled_request_is_counted_in_the_usage(self):
        install_throttle_log_handler()
        responses = [Throttled(raw_response(_DummyOutput(value="ok"), 100, 50))]
        llm = LLM(FakeChatModel(responses), _PYDANTIC_SCHEMA, max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage.throttled_requests == 1

    @pytest.mark.asyncio
    async def test_throttled_requests_are_summed_across_parse_attempts(self):
        install_throttle_log_handler()
        responses = [
            Throttled(raw_response({"unexpected": 1}, 100, 50)),
            Throttled(raw_response({"value": "ok"}, 100, 50)),
        ]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage.throttled_requests == 2


class TestMakeChatModel:
    def test_google_default_model_gets_minimal_thinking(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("GOOGLE_API_KEY", "dummy")
        settings = Settings(provider="google", model="", judge_model="", reasoning="")

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "model", None) == "gemini-3.5-flash-lite"
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

    def test_openai_builds_luna_at_reasoning_none(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENAI_API_KEY", "dummy")
        settings = Settings(provider="openai", model="", judge_model="", reasoning="")

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "model_name", None) == "gpt-6-luna"
        assert getattr(chat_model, "reasoning_effort", None) == "none"
        assert getattr(chat_model, "request_timeout", None) == 120
        assert getattr(chat_model, "max_tokens", None) == 8192

    def test_fireworks_builds_glm_at_medium_reasoning(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("FIREWORKS_API_KEY", "dummy")
        settings = Settings(provider="fireworks", model="", judge_model="", reasoning="")

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "model_name", None) == "accounts/fireworks/models/glm-5p3-flash"
        assert getattr(chat_model, "reasoning_effort", None) == "medium"
        assert getattr(chat_model, "request_timeout", None) == 120
        assert getattr(chat_model, "max_tokens", None) == 8192

    def test_fireworks_passes_an_explicit_reasoning(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("FIREWORKS_API_KEY", "dummy")
        settings = Settings(provider="fireworks", model="", judge_model="", reasoning="high")

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "reasoning_effort", None) == "high"

    def test_openai_without_its_key_raises_naming_it(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        settings = Settings(provider="openai", model="", judge_model="", reasoning="")

        with pytest.raises(ValueError, match="OPENAI_API_KEY"):
            make_chat_model(settings, settings.resolve_model())

    def test_openai_with_an_empty_key_raises_naming_it(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENAI_API_KEY", "")
        settings = Settings(provider="openai", model="", judge_model="", reasoning="")

        with pytest.raises(ValueError, match="OPENAI_API_KEY"):
            make_chat_model(settings, settings.resolve_model())

    def test_alibaba_builds_qwen_on_chat_completions_with_thinking_off(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("DASHSCOPE_API_KEY", "dummy")
        settings = Settings(provider="alibaba", model="", judge_model="", reasoning="")

        chat_model = make_chat_model(settings, settings.resolve_model())

        assert getattr(chat_model, "model_name", None) == "qwen3.8-flash"
        assert str(getattr(chat_model, "openai_api_base", "")) == (
            "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
        )
        assert getattr(chat_model, "extra_body", None) == {"enable_thinking": False}
        assert not getattr(chat_model, "use_responses_api", True)
        assert getattr(chat_model, "request_timeout", None) == 120
        assert getattr(chat_model, "max_tokens", None) == 8192

    @pytest.mark.parametrize("key", [None, ""])
    def test_alibaba_without_its_key_raises_naming_it(
        self, monkeypatch: pytest.MonkeyPatch, key: str | None
    ):
        if key is None:
            monkeypatch.delenv("DASHSCOPE_API_KEY", raising=False)
        else:
            monkeypatch.setenv("DASHSCOPE_API_KEY", key)
        settings = Settings(provider="alibaba", model="", judge_model="", reasoning="")

        with pytest.raises(ValueError, match="DASHSCOPE_API_KEY"):
            make_chat_model(settings, settings.resolve_model())
