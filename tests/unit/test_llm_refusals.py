# pyright: reportArgumentType=false
from typing import Any

import httpx2
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


def _permission_denied(body: dict[str, Any]) -> openai.PermissionDeniedError:
    request = httpx2.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
    response = httpx2.Response(403, request=request)
    return openai.PermissionDeniedError(f"Error code: 403 - {body}", response=response, body=body)


def _content_filtered(
    refusal: str | None, usage: CompletionUsage | None = None
) -> openai.ContentFilterFinishReasonError:
    completion = ChatCompletion(
        id="filtered",
        created=0,
        model="z-ai/glm-5.3",
        object="chat.completion",
        choices=[
            Choice(
                index=0,
                finish_reason="content_filter",
                message=ChatCompletionMessage(role="assistant", content=None, refusal=refusal),
            )
        ],
        usage=usage,
    )
    return openai.ContentFilterFinishReasonError(completion=completion)


_FILTERED_USAGE = CompletionUsage(
    prompt_tokens=100,
    completion_tokens=50,
    total_tokens=150,
    prompt_tokens_details=PromptTokensDetails(cached_tokens=20),
    completion_tokens_details=CompletionTokensDetails(reasoning_tokens=10),
)


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

        assert raised.value.usage == ProviderUsage(
            input_tokens=100, output_tokens=8192, largest_input_tokens=100
        )


class TestHostLevelBlock:
    @pytest.mark.parametrize("error_type", ["content_policy_violation", "refusal"])
    @pytest.mark.asyncio
    async def test_an_openrouter_403_block_raises_a_refusal_naming_the_host(self, error_type: str):
        metadata = {
            "error_type": error_type,
            "provider_name": "Sail Research",
            "provider_code": "1301",
        }
        error = _permission_denied({"message": "blocked", "metadata": metadata})
        llm = LLM(FakeChatModel([error]), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        message = raised.value.provider_message
        assert "blocked" in message
        assert "Sail Research" in message
        assert "1301" in message

    @pytest.mark.asyncio
    async def test_a_403_without_metadata_propagates_unchanged(self):
        error = _permission_denied({"message": "Guardrail blocked the request."})
        llm = LLM(FakeChatModel([error]), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(openai.PermissionDeniedError) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value is error

    @pytest.mark.asyncio
    async def test_a_content_filter_finish_with_a_refusal_raises_it_without_a_retry(self):
        llm = LLM(FakeChatModel([_content_filtered("I cannot help")]), _DICT_SCHEMA, 3)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.provider_message == "I cannot help"

    @pytest.mark.asyncio
    async def test_a_content_filter_finish_without_a_refusal_names_the_finish(self):
        llm = LLM(FakeChatModel([_content_filtered(None)]), _DICT_SCHEMA, 3)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.provider_message == "finish_reason content_filter"

    @pytest.mark.asyncio
    async def test_a_content_filter_finish_carries_the_usage_of_its_completion(self):
        llm = LLM(FakeChatModel([_content_filtered(None, _FILTERED_USAGE)]), _DICT_SCHEMA, 3)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.usage == ProviderUsage(
            input_tokens=100,
            output_tokens=50,
            cached_input_tokens=20,
            reasoning_tokens=10,
            largest_input_tokens=100,
        )

    @pytest.mark.asyncio
    async def test_a_content_filter_finish_after_a_cut_carries_the_usage_of_both(self):
        responses: list[dict[str, Any] | Exception] = [
            truncated(raw_response({"value": "cut"}, 100, 8192), finish_reason="length"),
            _content_filtered(None, _FILTERED_USAGE),
        ]
        llm = LLM(FakeChatModel(responses), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

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
        assert raised.value.usage == ProviderUsage(
            input_tokens=100, output_tokens=5, largest_input_tokens=100
        )

    @pytest.mark.asyncio
    async def test_an_anthropic_refusal_names_its_category(self):
        stop_details = {"type": "refusal", "category": "cyber", "explanation": None}
        refused = _with_raw(
            raw_response(None, 100, 5),
            response_metadata={"stop_reason": "refusal", "stop_details": stop_details},
        )
        llm = LLM(FakeChatModel([refused]), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(ProviderRefusal, match="category cyber"):
            await llm.generate_structured("prompt", _DummyOutput)

    @pytest.mark.parametrize(
        "stop_details",
        [None, {"type": "refusal", "category": None}, {"type": "refusal", "category": 3}],
    )
    @pytest.mark.asyncio
    async def test_an_anthropic_refusal_without_a_category_keeps_the_plain_message(
        self, stop_details: object
    ):
        refused = _with_raw(
            raw_response(None, 100, 5),
            response_metadata={"stop_reason": "refusal", "stop_details": stop_details},
        )
        llm = LLM(FakeChatModel([refused]), _DICT_SCHEMA, max_parse_attempts=3)

        with pytest.raises(ProviderRefusal) as raised:
            await llm.generate_structured("prompt", _DummyOutput)

        assert raised.value.provider_message == "Anthropic stopped the answer: stop_reason refusal"

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

        assert raised.value.usage == ProviderUsage(
            input_tokens=200, output_tokens=8197, largest_input_tokens=100
        )

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
