from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from mcp_auditor.domain.model_calls import MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.ports import LLMPort, ModelCallMissed


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
    except ModelCallMissed as missed:
        return _missed(call, missed)


def _missed(call: ModelCall[Any], missed: ModelCallMissed) -> Missed:
    missed_call = MissedModelCall(
        tool_name=call.tool_name, kind=call.kind, cause=missed.cause, detail=missed.detail
    )
    return Missed(missed_call, missed.usage)
