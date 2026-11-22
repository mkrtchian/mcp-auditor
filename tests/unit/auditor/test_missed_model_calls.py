import pytest

from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import Judgment, ProviderUsage
from mcp_auditor.domain.ports import (
    PromptTooLong,
    ProviderRefusal,
    ProviderThrottled,
    UnparseableOutput,
)
from mcp_auditor.graph.missed_model_calls import Missed, ModelCall, billed_usage, call_model
from tests.fakes import FakeLLM

JUDGMENT_CALL = ModelCall("read_file", ModelCallKind.JUDGMENT, "judge this", Judgment)


async def test_an_unreadable_answer_is_a_missed_model_call_with_its_usage():
    usage = ProviderUsage(input_tokens=40, output_tokens=12)

    outcome = await call_model(FakeLLM([UnparseableOutput(3, 1, usage)]), JUDGMENT_CALL)

    assert outcome == Missed(
        missed_call=MissedModelCall(
            tool_name="read_file",
            kind=ModelCallKind.JUDGMENT,
            cause=MissedCallCause.UNREADABLE_ANSWER,
            detail="no answer matched the expected format after 3 attempts"
            " (1 cut at the output limit)",
        ),
        usage=usage,
    )


async def test_a_refusal_is_a_missed_model_call_with_the_provider_message():
    usage = ProviderUsage(input_tokens=7, output_tokens=0)

    outcome = await call_model(
        FakeLLM([ProviderRefusal("flagged by policy", usage)]), JUDGMENT_CALL
    )

    assert outcome == Missed(
        missed_call=MissedModelCall(
            tool_name="read_file",
            kind=ModelCallKind.JUDGMENT,
            cause=MissedCallCause.PROVIDER_REFUSAL,
            detail="flagged by policy",
        ),
        usage=usage,
    )


async def test_a_throttled_call_is_a_missed_model_call_with_the_provider_message_and_its_429s():
    usage = ProviderUsage(throttled_requests=9)

    outcome = await call_model(
        FakeLLM([ProviderThrottled("Error code: 429 - slow down", 312.4, usage)]), JUDGMENT_CALL
    )

    assert outcome == Missed(
        missed_call=MissedModelCall(
            tool_name="read_file",
            kind=ModelCallKind.JUDGMENT,
            cause=MissedCallCause.PROVIDER_THROTTLED,
            detail="the model provider throttled the request past every retry"
            " (312 s waited by the auditor): Error code: 429 - slow down",
        ),
        usage=usage,
    )


async def test_a_prompt_too_long_is_a_missed_model_call_with_its_usage():
    usage = ProviderUsage(throttled_requests=2)

    outcome = await call_model(FakeLLM([PromptTooLong(usage)]), JUDGMENT_CALL)

    assert outcome == Missed(
        missed_call=MissedModelCall(
            tool_name="read_file",
            kind=ModelCallKind.JUDGMENT,
            cause=MissedCallCause.PROMPT_TOO_LONG,
            detail=str(PromptTooLong(usage)),
        ),
        usage=usage,
    )


@pytest.mark.parametrize(
    ("kind", "channels"),
    [
        (ModelCallKind.TEST_GENERATION, {"provider_usage"}),
        (ModelCallKind.JUDGMENT, {"provider_usage", "judge_usage"}),
        (ModelCallKind.CONTEXT_EXTRACTION, {"provider_usage"}),
        (ModelCallKind.CHAIN_PLANNING, {"provider_usage", "chain_usage"}),
        (ModelCallKind.CHAIN_STEP_OBSERVATION, {"provider_usage", "chain_usage"}),
        (ModelCallKind.CHAIN_STEP_PLANNING, {"provider_usage", "chain_usage"}),
        (ModelCallKind.CHAIN_JUDGMENT, {"provider_usage", "judge_usage", "chain_usage"}),
    ],
)
def test_a_model_call_is_billed_to_the_channels_of_its_kind(
    kind: ModelCallKind, channels: set[str]
):
    usage = ProviderUsage(input_tokens=5, output_tokens=3)

    assert billed_usage(kind, usage) == {channel: [usage] for channel in channels}
