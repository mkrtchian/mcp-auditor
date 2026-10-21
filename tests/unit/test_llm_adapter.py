import pytest

import tests.unit.support.test_llm_adapter_given as given
from mcp_auditor.adapters.throttling import install_throttle_log_handler
from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.ports import UnparseableOutput
from tests.fakes.chat_model import Throttled, raw_response, truncated


class TestTokenAccumulationOnRetry:
    async def test_usage_reflects_all_attempts_not_just_successful_one(self):
        responses = [
            raw_response(None, 100, 50, given.token_details(cache_read=30, reasoning=10)),
            raw_response(
                given.Output(value="ok"), 100, 50, given.token_details(cache_read=20, reasoning=5)
            ),
        ]
        llm = given.an_llm(responses, given.PYDANTIC_SCHEMA)

        _, usage = await llm.generate_structured("prompt", given.Output)

        assert usage == ProviderUsage(
            input_tokens=200,
            output_tokens=100,
            cached_input_tokens=50,
            reasoning_tokens=15,
            largest_input_tokens=100,
        )

    async def test_single_successful_attempt_returns_exact_usage(self):
        responses = [
            raw_response(parsed=given.Output(value="ok"), input_tokens=100, output_tokens=50),
        ]
        llm = given.an_llm(responses, given.PYDANTIC_SCHEMA)

        _, usage = await llm.generate_structured("prompt", given.Output)

        assert usage == ProviderUsage(input_tokens=100, output_tokens=50, largest_input_tokens=100)


class TestLargestRequest:
    async def test_the_largest_request_is_the_largest_attempt(self):
        responses = [
            raw_response({"unexpected": 1}, 300, 50),
            raw_response({"value": "ok"}, 120, 50),
        ]
        llm = given.an_llm(responses)

        _, usage = await llm.generate_structured("prompt", given.Output)

        assert usage.largest_input_tokens == 300

    async def test_a_cut_on_the_parse_path_counts_its_request(self):
        responses = [
            given.a_cut_completion(given.A_FULL_USAGE),
            raw_response(given.Output(value="ok"), 40, 50),
        ]
        llm = given.an_llm(responses)

        _, usage = await llm.generate_structured("prompt", given.Output)

        assert usage.largest_input_tokens == given.A_FULL_USAGE.prompt_tokens


class TestTokenDetails:
    async def test_details_fill_cached_input_and_reasoning_tokens(self):
        responses = [
            raw_response(
                given.Output(value="ok"), 100, 50, given.token_details(cache_read=40, reasoning=20)
            ),
        ]
        llm = given.an_llm(responses, given.PYDANTIC_SCHEMA)

        _, usage = await llm.generate_structured("prompt", given.Output)

        assert usage.cached_input_tokens == 40
        assert usage.reasoning_tokens == 20

    async def test_metadata_without_details_leaves_them_at_zero(self):
        llm = given.an_llm([raw_response(given.Output(value="ok"), 100, 50)], given.PYDANTIC_SCHEMA)

        _, usage = await llm.generate_structured("prompt", given.Output)

        assert usage.cached_input_tokens == 0
        assert usage.reasoning_tokens == 0


class TestDictSchema:
    async def test_a_dict_matching_the_schema_is_returned_as_the_model(self):
        llm = given.an_llm([raw_response({"value": "ok"}, 100, 50)])

        output, _ = await llm.generate_structured("prompt", given.Output)

        assert output == given.Output(value="ok")

    async def test_a_dict_failing_validation_is_retried_with_its_usage_counted(self):
        responses = [
            raw_response({"unexpected": 1}, 100, 50),
            raw_response({"value": "ok"}, 100, 50),
        ]
        llm = given.an_llm(responses)

        output, usage = await llm.generate_structured("prompt", given.Output)

        assert output == given.Output(value="ok")
        assert usage == ProviderUsage(input_tokens=200, output_tokens=100, largest_input_tokens=100)

    async def test_dicts_failing_validation_on_every_attempt_raise_with_the_usage_of_each(self):
        responses = [raw_response({"unexpected": 1}, 100, 50 + attempt) for attempt in range(3)]
        llm = given.an_llm(responses)

        with pytest.raises(
            UnparseableOutput, match="unparseable output after 3 attempts"
        ) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.usage == ProviderUsage(
            input_tokens=300, output_tokens=153, largest_input_tokens=100
        )
        assert raised.value.truncated_attempts == 0


class TestTruncatedOutput:
    async def test_an_incomplete_response_is_retried(self):
        responses = [
            truncated(raw_response(given.Output(value="cut"), 100, 4096), status="incomplete"),
            raw_response(given.Output(value="ok"), 100, 50),
        ]
        llm = given.an_llm(responses, given.PYDANTIC_SCHEMA)

        output, usage = await llm.generate_structured("prompt", given.Output)

        assert output == given.Output(value="ok")
        assert usage == ProviderUsage(
            input_tokens=200, output_tokens=4146, largest_input_tokens=100
        )

    async def test_the_raised_error_counts_the_truncated_attempts_and_their_usage(self):
        responses = [
            truncated(raw_response({"value": "cut"}, 100, 8192), finish_reason="length")
            for _ in range(2)
        ]
        llm = given.an_llm(responses, max_parse_attempts=2)

        with pytest.raises(UnparseableOutput) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.truncated_attempts == 2
        assert raised.value.usage == ProviderUsage(
            input_tokens=200, output_tokens=16384, largest_input_tokens=100
        )

    async def test_a_response_stopped_at_max_tokens_on_every_attempt_counts_as_truncated(self):
        responses = [
            truncated(raw_response(given.Output(value="cut"), 100, 8192), stop_reason="max_tokens")
            for _ in range(2)
        ]
        llm = given.an_llm(responses, given.PYDANTIC_SCHEMA, max_parse_attempts=2)

        with pytest.raises(UnparseableOutput) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.truncated_attempts == 2

    async def test_a_truncated_attempt_among_malformed_ones_is_counted_alone(self):
        responses = [
            truncated(raw_response({"value": "cut"}, 100, 8192), finish_reason="length"),
            raw_response({"unexpected": 1}, 100, 50),
            raw_response({"unexpected": 1}, 100, 50),
        ]
        llm = given.an_llm(responses)

        with pytest.raises(UnparseableOutput) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.truncated_attempts == 1

    async def test_a_cut_on_the_parse_path_on_every_attempt_counts_as_truncated(self):
        llm = given.an_llm([given.a_cut_completion(given.A_FULL_USAGE) for _ in range(3)])

        with pytest.raises(UnparseableOutput) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.truncated_attempts == 3
        assert raised.value.usage == ProviderUsage(
            input_tokens=300,
            output_tokens=150,
            cached_input_tokens=60,
            reasoning_tokens=30,
            largest_input_tokens=100,
        )

    async def test_a_cut_on_the_parse_path_is_retried(self):
        responses = [
            given.a_cut_completion(given.A_FULL_USAGE),
            raw_response(given.Output(value="ok"), 100, 50),
        ]
        llm = given.an_llm(responses)

        output, usage = await llm.generate_structured("prompt", given.Output)

        assert output == given.Output(value="ok")
        assert usage == ProviderUsage(
            input_tokens=200,
            output_tokens=100,
            cached_input_tokens=20,
            reasoning_tokens=10,
            largest_input_tokens=100,
        )

    async def test_a_cut_on_the_parse_path_without_usage_counts_no_tokens(self):
        llm = given.an_llm([given.a_cut_completion(None) for _ in range(3)])

        with pytest.raises(UnparseableOutput) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.truncated_attempts == 3
        assert raised.value.usage == ProviderUsage()


class TestThrottledRequests:
    async def test_a_throttled_request_is_counted_in_the_usage(self):
        install_throttle_log_handler()
        responses = [Throttled(raw_response(given.Output(value="ok"), 100, 50))]
        llm = given.an_llm(responses, given.PYDANTIC_SCHEMA)

        _, usage = await llm.generate_structured("prompt", given.Output)

        assert usage.throttled_requests == 1

    async def test_throttled_requests_are_summed_across_parse_attempts(self):
        install_throttle_log_handler()
        responses = [
            Throttled(raw_response({"unexpected": 1}, 100, 50)),
            Throttled(raw_response({"value": "ok"}, 100, 50)),
        ]
        llm = given.an_llm(responses)

        _, usage = await llm.generate_structured("prompt", given.Output)

        assert usage.throttled_requests == 2
