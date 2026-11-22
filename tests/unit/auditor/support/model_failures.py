from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.ports import (
    PromptTooLong,
    ProviderRefusal,
    ProviderThrottled,
    UnreadableAnswer,
)

REFUSAL_DETAIL = "flagged by policy"


def a_provider_refusal() -> ProviderRefusal:
    return ProviderRefusal(REFUSAL_DETAIL, ProviderUsage(input_tokens=7, output_tokens=0))


def an_unreadable_answer() -> UnreadableAnswer:
    return UnreadableAnswer(3, 1, ProviderUsage(input_tokens=40, output_tokens=12))


def a_provider_throttling() -> ProviderThrottled:
    return ProviderThrottled("slow down", 300.0, ProviderUsage(throttled_requests=8))


def a_prompt_too_long() -> PromptTooLong:
    return PromptTooLong(ProviderUsage(throttled_requests=2))


MODEL_FAILURES = {
    MissedCallCause.PROVIDER_REFUSAL: a_provider_refusal,
    MissedCallCause.UNREADABLE_ANSWER: an_unreadable_answer,
    MissedCallCause.PROVIDER_THROTTLED: a_provider_throttling,
    MissedCallCause.PROMPT_TOO_LONG: a_prompt_too_long,
}


def a_recorded_refusal(tool_name: str, kind: ModelCallKind) -> MissedModelCall:
    return MissedModelCall(
        tool_name=tool_name,
        kind=kind,
        cause=MissedCallCause.PROVIDER_REFUSAL,
        detail=REFUSAL_DETAIL,
    )
