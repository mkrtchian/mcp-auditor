from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from mcp_auditor.domain.models import AuditStep, ProviderUsage, RefusedStep, is_judge_step
from mcp_auditor.domain.ports import LLMPort, ProviderRefusal


@dataclass(frozen=True)
class ModelCall[T: BaseModel]:
    tool_name: str
    step: AuditStep
    prompt: str
    output_schema: type[T]


@dataclass(frozen=True)
class Refused:
    refused_step: RefusedStep
    usage: ProviderUsage
    is_judge: bool

    def state_update(self) -> dict[str, Any]:
        update: dict[str, Any] = {
            "refused_steps": [self.refused_step],
            "provider_usage": [self.usage],
        }
        if self.is_judge:
            update["judge_usage"] = [self.usage]
        return update


async def call_model[T: BaseModel](
    llm: LLMPort, call: ModelCall[T]
) -> tuple[T, ProviderUsage] | Refused:
    try:
        return await llm.generate_structured(call.prompt, call.output_schema)
    except ProviderRefusal as refusal:
        step = RefusedStep(
            tool_name=call.tool_name, step=call.step, provider_message=refusal.provider_message
        )
        return Refused(refused_step=step, usage=refusal.usage, is_judge=is_judge_step(call.step))
