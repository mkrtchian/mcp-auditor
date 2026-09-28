# pyright: reportArgumentType=false
from typing import Any

import httpx2
import openai
import pytest
from pydantic import BaseModel

from mcp_auditor.adapters.llm import LLM, StructuredOutput
from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.ports import ProviderRefusal
from tests.fakes.chat_model import FakeChatModel, raw_response, truncated


class _DummyOutput(BaseModel):
    value: str


_DICT_SCHEMA = StructuredOutput(method="json_schema", schema_as_dict=True)


_OPENAI_POLICY_MESSAGE = (
    "Invalid prompt: your prompt was flagged as potentially violating our usage policy."
)


def _bad_request(message: str, code: str | None) -> openai.BadRequestError:
    request = httpx2.Request("POST", "https://api.example.test/v1/responses")
    response = httpx2.Response(400, request=request)
    body = {"message": message, "type": "invalid_request_error", "code": code}
    return openai.BadRequestError(f"Error code: 400 - {body}", response=response, body=body)


def _wrapped(cause: Exception) -> Exception:
    try:
        raise RuntimeError("wrapper") from cause
    except RuntimeError as wrapper:
        return wrapper


def _with_raw(response: dict[str, Any], **raw_fields: Any) -> dict[str, Any]:
    for name, value in raw_fields.items():
        setattr(response["raw"], name, value)
    return response


class TestRefusalAsAnError:
    @pytest.mark.asyncio
    async def test_openai_invalid_prompt_raises_a_refusal_carrying_the_message(self):
        error = _bad_request(_OPENAI_POLICY_MESSAGE, code="invalid_prompt")
        llm = LLM(FakeChatModel([error]), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.provider_message == _OPENAI_POLICY_MESSAGE
        assert raised.value.usage == ProviderUsage()

    @pytest.mark.asyncio
    async def test_a_refusal_wrapped_as_the_cause_of_another_error_is_recognized(self):
        error = _wrapped(_bad_request(_OPENAI_POLICY_MESSAGE, code="invalid_prompt"))
        llm = LLM(FakeChatModel([error]), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(ProviderRefusal, match="usage policy"):
            await llm.generate_structured("prompt", _DummyOutput)

    @pytest.mark.asyncio
    async def test_alibaba_data_inspection_failure_raises_a_refusal(self):
        error = _bad_request(
            "Input data may contain inappropriate content.", "data_inspection_failed"
        )
        llm = LLM(FakeChatModel([error]), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(ProviderRefusal, match="inappropriate content"):
            await llm.generate_structured("prompt", _DummyOutput)

    @pytest.mark.parametrize(
        "message",
        [
            "<400> InternalError.Algo.DataInspectionFailed: Input data may contain "
            "inappropriate content.",
            _OPENAI_POLICY_MESSAGE,
        ],
    )
    @pytest.mark.asyncio
    async def test_a_refusal_without_a_code_is_recognized_by_its_wording(self, message: str):
        llm = LLM(FakeChatModel([_bad_request(message, code=None)]), _DICT_SCHEMA, 3)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.provider_message == message

    @pytest.mark.asyncio
    async def test_another_bad_request_propagates_unchanged(self):
        error = _bad_request("Too many tokens.", code="context_length_exceeded")
        llm = LLM(FakeChatModel([error]), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(openai.BadRequestError) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value is error

    @pytest.mark.asyncio
    async def test_a_refusal_after_a_truncated_attempt_carries_its_usage(self):
        responses: list[dict[str, Any] | Exception] = [
            truncated(raw_response({"value": "cut"}, 100, 8192), finish_reason="length"),
            _bad_request(_OPENAI_POLICY_MESSAGE, code="invalid_prompt"),
        ]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.usage == ProviderUsage(input_tokens=100, output_tokens=8192)


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
    @pytest.mark.asyncio
    async def test_a_refused_answer_raises_without_a_retry(self, raw_fields: dict[str, Any]):
        responses: list[dict[str, Any] | Exception] = [
            _with_raw(raw_response(None, 100, 5), **raw_fields),
            raw_response({"value": "ok"}, 100, 50),
        ]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.provider_message
        assert raised.value.usage == ProviderUsage(input_tokens=100, output_tokens=5)

    @pytest.mark.asyncio
    async def test_the_model_refusal_text_becomes_the_provider_message(self):
        refused = _with_raw(
            raw_response(None, 100, 5),
            content=[{"type": "refusal", "refusal": "I can't help with that."}],
        )
        llm = LLM(FakeChatModel([refused]), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(ProviderRefusal, match="can't help with that"):
            await llm.generate_structured("prompt", _DummyOutput)

    @pytest.mark.asyncio
    async def test_a_refusal_on_the_second_attempt_carries_the_usage_of_both(self):
        responses: list[dict[str, Any] | Exception] = [
            truncated(raw_response({"value": "cut"}, 100, 8192), finish_reason="length"),
            _with_raw(raw_response(None, 100, 5), response_metadata={"stop_reason": "refusal"}),
        ]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.usage == ProviderUsage(input_tokens=200, output_tokens=8197)

    @pytest.mark.asyncio
    async def test_a_normal_google_stop_is_not_a_refusal(self):
        answered = _with_raw(
            raw_response({"value": "ok"}, 100, 50),
            response_metadata={
                "finish_reason": "STOP",
                "prompt_feedback": {"block_reason": 0, "safety_ratings": []},
            },
        )
        llm = LLM(FakeChatModel([answered]), _DICT_SCHEMA, max_parse_attempts=3)

        output, _ = await llm.generate_structured("prompt", _DummyOutput)

        assert output == _DummyOutput(value="ok")
