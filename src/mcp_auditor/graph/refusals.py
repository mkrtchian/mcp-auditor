from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from mcp_auditor.domain.models import AuditStep, ProviderUsage, RefusedStep
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

    def state_update(self) -> dict[str, Any]:
        return {"refused_steps": [self.refused_step], "provider_usage": [self.usage]}


async def call_model[T: BaseModel](
    llm: LLMPort, call: ModelCall[T]
) -> tuple[T, ProviderUsage] | Refused:
    try:
        return await llm.generate_structured(call.prompt, call.output_schema)
    except ProviderRefusal as refusal:
        step = RefusedStep(
            tool_name=call.tool_name, step=call.step, provider_message=refusal.provider_message
        )
        return Refused(refused_step=step, usage=refusal.usage)
