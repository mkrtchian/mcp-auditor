# pyright: reportArgumentType=false
import openai
import pytest
from openai.types.chat import ChatCompletion
from openai.types.chat.chat_completion import Choice
from openai.types.chat.chat_completion_message import ChatCompletionMessage
from openai.types.completion_usage import (
    CompletionTokensDetails,
    CompletionUsage,
    PromptTokensDetails,
)
from pydantic import BaseModel

from mcp_auditor.adapters.llm import LLM, StructuredOutput
from mcp_auditor.adapters.throttling import install_throttle_log_handler
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


def _cut_completion(usage: CompletionUsage | None) -> openai.LengthFinishReasonError:
    completion = ChatCompletion(
        id="cut",
        created=0,
        model="qwen",
        object="chat.completion",
        choices=[
            Choice(
                index=0,
                finish_reason="length",
                message=ChatCompletionMessage(role="assistant", content='{"value": "c'),
            )
        ],
        usage=usage,
    )
    return openai.LengthFinishReasonError(completion=completion)


_CUT_USAGE = CompletionUsage(
    prompt_tokens=100,
    completion_tokens=50,
    total_tokens=150,
    prompt_tokens_details=PromptTokensDetails(cached_tokens=20),
    completion_tokens_details=CompletionTokensDetails(reasoning_tokens=10),
)


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
            input_tokens=200,
            output_tokens=100,
            cached_input_tokens=50,
            reasoning_tokens=15,
            largest_input_tokens=100,
        )

    @pytest.mark.asyncio
    async def test_single_successful_attempt_returns_exact_usage(self):
        responses = [
            raw_response(parsed=_DummyOutput(value="ok"), input_tokens=100, output_tokens=50),
        ]
        llm = LLM(FakeChatModel(responses), _PYDANTIC_SCHEMA, max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage == ProviderUsage(input_tokens=100, output_tokens=50, largest_input_tokens=100)


class TestLargestRequest:
    @pytest.mark.asyncio
    async def test_the_largest_request_is_the_largest_attempt(self):
        responses = [
            raw_response({"unexpected": 1}, 300, 50),
            raw_response({"value": "ok"}, 120, 50),
        ]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage.largest_input_tokens == 300

    @pytest.mark.asyncio
    async def test_a_cut_on_the_parse_path_counts_its_request(self):
        responses = [_cut_completion(_CUT_USAGE), raw_response(_DummyOutput(value="ok"), 40, 50)]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        _, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert usage.largest_input_tokens == _CUT_USAGE.prompt_tokens


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
        assert usage == ProviderUsage(input_tokens=200, output_tokens=100, largest_input_tokens=100)

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

        assert raised.value.usage == ProviderUsage(
            input_tokens=300, output_tokens=153, largest_input_tokens=100
        )
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
        assert usage == ProviderUsage(
            input_tokens=200, output_tokens=4146, largest_input_tokens=100
        )

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
        assert raised.value.usage == ProviderUsage(
            input_tokens=200, output_tokens=16384, largest_input_tokens=100
        )

    @pytest.mark.asyncio
    async def test_a_response_stopped_at_max_tokens_on_every_attempt_counts_as_truncated(self):
        responses = [
            truncated(raw_response(_DummyOutput(value="cut"), 100, 8192), stop_reason="max_tokens")
            for _ in range(2)
        ]
        llm = LLM(FakeChatModel(responses), _PYDANTIC_SCHEMA, max_parse_attempts=2)

        with pytest.raises(UnparseableOutput) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.truncated_attempts == 2

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

    @pytest.mark.asyncio
    async def test_a_cut_on_the_parse_path_on_every_attempt_counts_as_truncated(self):
        responses = [_cut_completion(_CUT_USAGE) for _ in range(3)]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(UnparseableOutput) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.truncated_attempts == 3
        assert raised.value.usage == ProviderUsage(
            input_tokens=300,
            output_tokens=150,
            cached_input_tokens=60,
            reasoning_tokens=30,
            largest_input_tokens=100,
        )

    @pytest.mark.asyncio
    async def test_a_cut_on_the_parse_path_is_retried(self):
        responses = [_cut_completion(_CUT_USAGE), raw_response(_DummyOutput(value="ok"), 100, 50)]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        output, usage = await llm.generate_structured("prompt", _DummyOutput)

        assert output == _DummyOutput(value="ok")
        assert usage == ProviderUsage(
            input_tokens=200,
            output_tokens=100,
            cached_input_tokens=20,
            reasoning_tokens=10,
            largest_input_tokens=100,
        )

    @pytest.mark.asyncio
    async def test_a_cut_on_the_parse_path_without_usage_counts_no_tokens(self):
        responses = [_cut_completion(None) for _ in range(3)]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(UnparseableOutput) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.truncated_attempts == 3
        assert raised.value.usage == ProviderUsage()


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
