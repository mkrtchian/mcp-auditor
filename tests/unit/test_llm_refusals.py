from typing import Any

import openai
import pytest

import tests.unit.support.test_llm_refusals_given as given
from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.ports import ProviderRefusal
from tests.fakes.chat_model import raw_response, truncated


class TestRefusalAsAnError:
    async def test_openai_invalid_prompt_raises_a_refusal_carrying_the_message(self):
        error = given.a_bad_request(given.OPENAI_POLICY_MESSAGE, code="invalid_prompt")
        llm = given.an_llm([error])

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.provider_message == given.OPENAI_POLICY_MESSAGE
        assert raised.value.usage == ProviderUsage()

    async def test_a_refusal_wrapped_as_the_cause_of_another_error_is_recognized(self):
        error = given.wrapped(
            given.a_bad_request(given.OPENAI_POLICY_MESSAGE, code="invalid_prompt")
        )
        llm = given.an_llm([error])

        with pytest.raises(ProviderRefusal, match="usage policy"):
            await llm.generate_structured("prompt", given.Output)

    async def test_alibaba_data_inspection_failure_raises_a_refusal(self):
        error = given.a_bad_request(
            "Input data may contain inappropriate content.", "data_inspection_failed"
        )
        llm = given.an_llm([error])

        with pytest.raises(ProviderRefusal, match="inappropriate content"):
            await llm.generate_structured("prompt", given.Output)

    @pytest.mark.parametrize(
        "message",
        [
            "<400> InternalError.Algo.DataInspectionFailed: Input data may contain "
            "inappropriate content.",
            given.OPENAI_POLICY_MESSAGE,
        ],
    )
    async def test_a_refusal_without_a_code_is_recognized_by_its_wording(self, message: str):
        llm = given.an_llm([given.a_bad_request(message, code=None)])

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.provider_message == message

    async def test_another_bad_request_propagates_unchanged(self):
        error = given.a_bad_request("Too many tokens.", code="context_length_exceeded")
        llm = given.an_llm([error])

        with pytest.raises(openai.BadRequestError) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value is error

    async def test_a_refusal_after_a_truncated_attempt_carries_its_usage(self):
        responses: list[dict[str, Any] | Exception] = [
            truncated(raw_response({"value": "cut"}, 100, 8192), finish_reason="length"),
            given.a_bad_request(given.OPENAI_POLICY_MESSAGE, code="invalid_prompt"),
        ]
        llm = given.an_llm(responses)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.usage == ProviderUsage(
            input_tokens=100, output_tokens=8192, largest_input_tokens=100
        )


class TestHostLevelBlock:
    @pytest.mark.parametrize("error_type", ["content_policy_violation", "refusal"])
    async def test_an_openrouter_403_block_raises_a_refusal_naming_the_host(self, error_type: str):
        metadata = {
            "error_type": error_type,
            "provider_name": "Sail Research",
            "provider_code": "1301",
        }
        error = given.a_permission_denied({"message": "blocked", "metadata": metadata})
        llm = given.an_llm([error])

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", given.Output)

        message = raised.value.provider_message
        assert "blocked" in message
        assert "Sail Research" in message
        assert "1301" in message

    async def test_a_403_without_metadata_propagates_unchanged(self):
        error = given.a_permission_denied({"message": "Guardrail blocked the request."})
        llm = given.an_llm([error])

        with pytest.raises(openai.PermissionDeniedError) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value is error

    async def test_a_content_filter_finish_with_a_refusal_raises_it_without_a_retry(self):
        llm = given.an_llm([given.a_content_filtered("I cannot help")])

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.provider_message == "I cannot help"

    async def test_a_content_filter_finish_without_a_refusal_names_the_finish(self):
        llm = given.an_llm([given.a_content_filtered(None)])

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.provider_message == "finish_reason content_filter"

    async def test_a_content_filter_finish_carries_the_usage_of_its_completion(self):
        llm = given.an_llm([given.a_content_filtered(None, given.A_FULL_USAGE)])

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.usage == ProviderUsage(
            input_tokens=100,
            output_tokens=50,
            cached_input_tokens=20,
            reasoning_tokens=10,
            largest_input_tokens=100,
        )

    async def test_a_content_filter_finish_after_a_cut_carries_the_usage_of_both(self):
        responses: list[dict[str, Any] | Exception] = [
            truncated(raw_response({"value": "cut"}, 100, 8192), finish_reason="length"),
            given.a_content_filtered(None, given.A_FULL_USAGE),
        ]
        llm = given.an_llm(responses)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.usage == ProviderUsage(
            input_tokens=200,
            output_tokens=8242,
            cached_input_tokens=20,
            reasoning_tokens=10,
            largest_input_tokens=100,
        )


class TestRefusalInTheResponse:
    @pytest.mark.parametrize(
        "raw_fields",
        [
            pytest.param({"response_metadata": {"stop_reason": "refusal"}}, id="anthropic"),
            pytest.param({"response_metadata": {"finish_reason": "SAFETY"}}, id="google-safety"),
            pytest.param(
                {"response_metadata": {"finish_reason": "PROHIBITED_CONTENT"}},
                id="google-prohibited",
            ),
            pytest.param(
                {"response_metadata": {"prompt_feedback": {"block_reason": "SAFETY"}}},
                id="google-prompt-block",
            ),
            pytest.param(
                {"additional_kwargs": {"refusal": "I can't help with that."}},
                id="openai-chat-completions",
            ),
            pytest.param(
                {"content": [{"type": "refusal", "refusal": "I can't help with that."}]},
                id="openai-responses",
            ),
        ],
    )
    async def test_a_refused_answer_raises_without_a_retry(self, raw_fields: dict[str, Any]):
        responses: list[dict[str, Any] | Exception] = [
            given.with_raw(raw_response(None, 100, 5), **raw_fields),
            raw_response({"value": "ok"}, 100, 50),
        ]
        llm = given.an_llm(responses)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.provider_message
        assert raised.value.usage == ProviderUsage(
            input_tokens=100, output_tokens=5, largest_input_tokens=100
        )

    async def test_an_anthropic_refusal_names_its_category(self):
        stop_details = {"type": "refusal", "category": "cyber", "explanation": None}
        refused = given.with_raw(
            raw_response(None, 100, 5),
            response_metadata={"stop_reason": "refusal", "stop_details": stop_details},
        )
        llm = given.an_llm([refused])

        with pytest.raises(ProviderRefusal, match="category cyber"):
            await llm.generate_structured("prompt", given.Output)

    @pytest.mark.parametrize(
        "stop_details",
        [None, {"type": "refusal", "category": None}, {"type": "refusal", "category": 3}],
    )
    async def test_an_anthropic_refusal_without_a_category_keeps_the_plain_message(
        self, stop_details: object
    ):
        refused = given.with_raw(
            raw_response(None, 100, 5),
            response_metadata={"stop_reason": "refusal", "stop_details": stop_details},
        )
        llm = given.an_llm([refused])

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.provider_message == "Anthropic stopped the answer: stop_reason refusal"

    async def test_the_model_refusal_text_becomes_the_provider_message(self):
        refused = given.with_raw(
            raw_response(None, 100, 5),
            content=[{"type": "refusal", "refusal": "I can't help with that."}],
        )
        llm = given.an_llm([refused])

        with pytest.raises(ProviderRefusal, match="can't help with that"):
            await llm.generate_structured("prompt", given.Output)

    async def test_a_refusal_on_the_second_attempt_carries_the_usage_of_both(self):
        responses: list[dict[str, Any] | Exception] = [
            truncated(raw_response({"value": "cut"}, 100, 8192), finish_reason="length"),
            given.with_raw(
                raw_response(None, 100, 5), response_metadata={"stop_reason": "refusal"}
            ),
        ]
        llm = given.an_llm(responses)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", given.Output)

        assert raised.value.usage == ProviderUsage(
            input_tokens=200, output_tokens=8197, largest_input_tokens=100
        )

    async def test_a_normal_google_stop_is_not_a_refusal(self):
        answered = given.with_raw(
            raw_response({"value": "ok"}, 100, 50),
            response_metadata={
                "finish_reason": "STOP",
                "prompt_feedback": {"block_reason": 0, "safety_ratings": []},
            },
        )
        llm = given.an_llm([answered])

        output, _ = await llm.generate_structured("prompt", given.Output)

        assert output == given.Output(value="ok")
