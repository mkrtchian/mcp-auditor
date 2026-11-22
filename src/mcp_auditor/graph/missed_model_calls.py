from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.ports import (
    LLMPort,
    PromptTooLong,
    ProviderRefusal,
    ProviderThrottled,
    UnparseableOutput,
)


@dataclass(frozen=True)
class ModelCall[T: BaseModel]:
    tool_name: str
    kind: ModelCallKind
    prompt: str
    output_schema: type[T]

    def billed(self, usage: ProviderUsage) -> dict[str, list[ProviderUsage]]:
        return billed_usage(self.kind, usage)


@dataclass(frozen=True)
class Missed:
    missed_call: MissedModelCall
    usage: ProviderUsage

    def state_update(self) -> dict[str, Any]:
        return {
            "missed_model_calls": [self.missed_call],
            **billed_usage(self.missed_call.kind, self.usage),
        }


_JUDGE_CALLS = frozenset({ModelCallKind.JUDGMENT, ModelCallKind.CHAIN_JUDGMENT})
_CHAIN_CALLS = frozenset(
    {
        ModelCallKind.CHAIN_PLANNING,
        ModelCallKind.CHAIN_STEP_OBSERVATION,
        ModelCallKind.CHAIN_STEP_PLANNING,
        ModelCallKind.CHAIN_JUDGMENT,
    }
)


def billed_usage(kind: ModelCallKind, usage: ProviderUsage) -> dict[str, list[ProviderUsage]]:
    billed = {"provider_usage": [usage]}
    if kind in _JUDGE_CALLS:
        billed["judge_usage"] = [usage]
    if kind in _CHAIN_CALLS:
        billed["chain_usage"] = [usage]
    return billed


async def call_model[T: BaseModel](
    llm: LLMPort, call: ModelCall[T]
) -> tuple[T, ProviderUsage] | Missed:
    try:
        return await llm.generate_structured(call.prompt, call.output_schema)
    except ProviderRefusal as refusal:
        return _missed(
            call, MissedCallCause.PROVIDER_REFUSAL, refusal.provider_message, refusal.usage
        )
    except UnparseableOutput as unreadable:
        detail = (
            f"no answer matched the expected format after {unreadable.attempts} attempts"
            f" ({unreadable.truncated_attempts} cut at the output limit)"
        )
        return _missed(call, MissedCallCause.UNREADABLE_ANSWER, detail, unreadable.usage)
    except ProviderThrottled as throttled:
        return _missed(call, MissedCallCause.PROVIDER_THROTTLED, str(throttled), throttled.usage)
    except PromptTooLong as too_long:
        return _missed(call, MissedCallCause.PROMPT_TOO_LONG, str(too_long), too_long.usage)


def _missed(
    call: ModelCall[Any], cause: MissedCallCause, detail: str, usage: ProviderUsage
) -> Missed:
    missed_call = MissedModelCall(
        tool_name=call.tool_name, kind=call.kind, cause=cause, detail=detail
    )
    return Missed(missed_call, usage)
