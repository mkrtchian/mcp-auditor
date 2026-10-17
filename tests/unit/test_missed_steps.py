from mcp_auditor.domain import Judgment, ProviderUsage
from mcp_auditor.domain.models import AuditStep, MissCause, MissedStep
from mcp_auditor.domain.ports import ProviderRefusal, UnparseableOutput
from mcp_auditor.graph.missed_steps import Missed, ModelCall, call_model
from tests.fakes import FakeLLM

JUDGMENT_CALL = ModelCall("read_file", AuditStep.JUDGMENT, "judge this", Judgment)


async def test_an_unreadable_answer_is_a_missed_step_with_its_usage():
    usage = ProviderUsage(input_tokens=40, output_tokens=12)

    outcome = await call_model(FakeLLM([UnparseableOutput(3, 1, usage)]), JUDGMENT_CALL)

    assert outcome == Missed(
        missed_step=MissedStep(
            tool_name="read_file",
            step=AuditStep.JUDGMENT,
            cause=MissCause.UNREADABLE_ANSWER,
            detail="no answer matched the expected format after 3 attempts"
            " (1 cut at the output limit)",
        ),
        usage=usage,
        is_judge=True,
    )


async def test_a_refusal_is_a_missed_step_with_the_provider_message():
    usage = ProviderUsage(input_tokens=7, output_tokens=0)

    outcome = await call_model(
        FakeLLM([ProviderRefusal("flagged by policy", usage)]), JUDGMENT_CALL
    )

    assert outcome == Missed(
        missed_step=MissedStep(
            tool_name="read_file",
            step=AuditStep.JUDGMENT,
            cause=MissCause.PROVIDER_REFUSAL,
            detail="flagged by policy",
        ),
        usage=usage,
        is_judge=True,
    )
