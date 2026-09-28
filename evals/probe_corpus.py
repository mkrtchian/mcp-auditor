"""The probe corpus: the prompts the reference model answered during one capture run.

Only prompts are kept. The probe replays them against each candidate, so a
reference response or verdict would be dead weight, and a judge sample drawn by
looking at responses would be biased.
"""

import random
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from mcp_auditor.domain.models import (
    AttackContext,
    AuditPayload,
    ChainPlanBatch,
    Judgment,
    ProviderUsage,
    StepObservation,
    TestCaseBatch,
)
from mcp_auditor.domain.ports import LLMPort

type Role = Literal["main", "judge"]


class ProbeCall(BaseModel):
    call_id: str
    schema_name: str
    role: Role
    source: Literal["honeypot", "cve"]
    prompt: str


class ReferenceConditions(BaseModel):
    provider: str
    model: str
    judge_model: str
    reasoning: str | None
    judge_reasoning: str | None


class ProbeCorpus(BaseModel):
    captured_at: str
    commit: str
    reference: ReferenceConditions
    budget: int
    judge_sample_seed: int
    judge_calls_captured: int
    calls: list[ProbeCall]


class RecordingLLM:
    def __init__(self, inner: LLMPort, role: Role, sink: list[ProbeCall]) -> None:
        self._inner = inner
        self._role: Role = role
        self._sink = sink

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]:
        schema_name = output_schema.__name__
        self._sink.append(
            ProbeCall(
                call_id=f"honeypot/{schema_name}/{len(self._sink):03d}",
                schema_name=schema_name,
                role=self._role,
                source="honeypot",
                prompt=prompt,
            )
        )
        return await self._inner.generate_structured(prompt, output_schema)


def sample_judge_calls(calls: list[ProbeCall], size: int, seed: int) -> list[ProbeCall]:
    judge_positions = [index for index, call in enumerate(calls) if call.role == "judge"]
    if len(judge_positions) < size:
        raise ValueError(
            f"Cannot sample {size} judge calls: only {len(judge_positions)} were captured."
        )
    kept = set(random.Random(seed).sample(judge_positions, size))
    return [call for index, call in enumerate(calls) if call.role != "judge" or index in kept]


_SCHEMAS: dict[str, type[BaseModel]] = {
    schema.__name__: schema
    for schema in (
        TestCaseBatch,
        Judgment,
        AttackContext,
        ChainPlanBatch,
        StepObservation,
        AuditPayload,
    )
}

SCHEMA_NAMES = list(_SCHEMAS)


def schema_for(schema_name: str) -> type[BaseModel]:
    if schema_name not in _SCHEMAS:
        raise ValueError(f"Unknown schema name in the probe corpus: {schema_name!r}")
    return _SCHEMAS[schema_name]


def load_corpus(path: Path) -> ProbeCorpus:
    return ProbeCorpus.model_validate_json(path.read_text())


def write_corpus(path: Path, corpus: ProbeCorpus) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(corpus.model_dump_json(indent=2) + "\n")
