from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from mcp_auditor.domain.models import (
    AuditStep,
    MissCause,
    MissedStep,
    ProviderUsage,
    is_judge_step,
)
from mcp_auditor.domain.ports import LLMPort, ProviderRefusal, UnparseableOutput


@dataclass(frozen=True)
class ModelCall[T: BaseModel]:
    tool_name: str
    step: AuditStep
    prompt: str
    output_schema: type[T]


@dataclass(frozen=True)
class Missed:
    missed_step: MissedStep
    usage: ProviderUsage
    is_judge: bool

    def state_update(self) -> dict[str, Any]:
        update: dict[str, Any] = {
            "missed_steps": [self.missed_step],
            "provider_usage": [self.usage],
        }
        if self.is_judge:
            update["judge_usage"] = [self.usage]
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


def _missed(call: ModelCall[Any], cause: MissCause, detail: str, usage: ProviderUsage) -> Missed:
    step = MissedStep(tool_name=call.tool_name, step=call.step, cause=cause, detail=detail)
    return Missed(missed_step=step, usage=usage, is_judge=is_judge_step(call.step))
