from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from mcp_auditor.domain.models import (
    MissCause,
    MissedModelCall,
    ModelCallKind,
    ProviderUsage,
    is_chain_call,
    is_judge_call,
)
from mcp_auditor.domain.ports import (
    LLMPort,
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


@dataclass(frozen=True)
class Missed:
    missed_call: MissedModelCall
    usage: ProviderUsage
    is_judge: bool
    is_chain: bool

    def state_update(self) -> dict[str, Any]:
        update: dict[str, Any] = {
            "missed_model_calls": [self.missed_call],
            "provider_usage": [self.usage],
        }
        if self.is_judge:
            update["judge_usage"] = [self.usage]
        if self.is_chain:
            update["chain_usage"] = [self.usage]
        return update


async def call_model[T: BaseModel](
    llm: LLMPort, call: ModelCall[T]
) -> tuple[T, ProviderUsage] | Missed:
    try:
        return await llm.generate_structured(call.prompt, call.output_schema)
    except ProviderRefusal as refusal:
        return _missed(call, MissCause.PROVIDER_REFUSAL, refusal.provider_message, refusal.usage)
    except UnparseableOutput as unreadable:
        detail = (
            f"no answer matched the expected format after {unreadable.attempts} attempts"
            f" ({unreadable.truncated_attempts} cut at the output limit)"
        )
        return _missed(call, MissCause.UNREADABLE_ANSWER, detail, unreadable.usage)
    except ProviderThrottled as throttled:
        return _missed(call, MissCause.PROVIDER_THROTTLED, str(throttled), throttled.usage)


def _missed(call: ModelCall[Any], cause: MissCause, detail: str, usage: ProviderUsage) -> Missed:
    missed_call = MissedModelCall(
        tool_name=call.tool_name, kind=call.kind, cause=cause, detail=detail
    )
    return Missed(
        missed_call=missed_call,
        usage=usage,
        is_judge=is_judge_call(call.kind),
        is_chain=is_chain_call(call.kind),
    )
