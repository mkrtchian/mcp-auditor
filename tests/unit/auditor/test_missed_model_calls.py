from mcp_auditor.domain import Judgment, ProviderUsage
from mcp_auditor.domain.models import MissCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.ports import ProviderRefusal, ProviderThrottled, UnparseableOutput
from mcp_auditor.graph.missed_model_calls import Missed, ModelCall, call_model
from tests.fakes import FakeLLM

JUDGMENT_CALL = ModelCall("read_file", ModelCallKind.JUDGMENT, "judge this", Judgment)


async def test_an_unreadable_answer_is_a_missed_step_with_its_usage():
    usage = ProviderUsage(input_tokens=40, output_tokens=12)

    outcome = await call_model(FakeLLM([UnparseableOutput(3, 1, usage)]), JUDGMENT_CALL)

    assert outcome == Missed(
        missed_call=MissedModelCall(
            tool_name="read_file",
            kind=ModelCallKind.JUDGMENT,
            cause=MissCause.UNREADABLE_ANSWER,
            detail="no answer matched the expected format after 3 attempts"
            " (1 cut at the output limit)",
        ),
        usage=usage,
        is_judge=True,
        is_chain=False,
    )


async def test_a_refusal_is_a_missed_step_with_the_provider_message():
    usage = ProviderUsage(input_tokens=7, output_tokens=0)

    outcome = await call_model(
        FakeLLM([ProviderRefusal("flagged by policy", usage)]), JUDGMENT_CALL
    )

    assert outcome == Missed(
        missed_call=MissedModelCall(
            tool_name="read_file",
            kind=ModelCallKind.JUDGMENT,
            cause=MissCause.PROVIDER_REFUSAL,
            detail="flagged by policy",
        ),
        usage=usage,
        is_judge=True,
        is_chain=False,
    )


async def test_a_throttled_call_is_a_missed_step_with_the_provider_message_and_its_429s():
    usage = ProviderUsage(throttled_requests=9)

    outcome = await call_model(
        FakeLLM([ProviderThrottled("Error code: 429 - slow down", 312.4, usage)]), JUDGMENT_CALL
    )

    assert outcome == Missed(
        missed_call=MissedModelCall(
            tool_name="read_file",
            kind=ModelCallKind.JUDGMENT,
            cause=MissCause.PROVIDER_THROTTLED,
            detail="the model provider throttled the request past every retry"
            " (312 s waited by the auditor): Error code: 429 - slow down",
        ),
        usage=usage,
        is_judge=True,
        is_chain=False,
    )
