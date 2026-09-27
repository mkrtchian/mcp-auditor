"""The faults the fault injection harness plants in the audit, around the production models.

What each fault models and what the gate is expected to do with it are in
`evals/fault_injection_method.md`.
"""

import random
from typing import cast

from pydantic import BaseModel

from evals.gate import cell_key
from evals.metrics import VerdictMap
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    ChainPlanBatch,
    EvalVerdict,
    Judgment,
    Severity,
    StepObservation,
    TestCaseBatch,
    TokenUsage,
)
from mcp_auditor.domain.ports import LLMPort, ProviderRefusal

_NO_USAGE = TokenUsage()
_CHAIN_SCHEMAS: tuple[type[BaseModel], ...] = (ChainPlanBatch, StepObservation, AuditPayload)


class PassingJudge:
    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, TokenUsage]:
        return _judgment(output_schema, EvalVerdict.PASS)


class FailingJudge:
    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, TokenUsage]:
        return _judgment(output_schema, EvalVerdict.FAIL)


class RandomJudge:
    """Fails each case with probability 0.5, one seeded draw per call."""

    def __init__(self, seed: int) -> None:
        self._draws = random.Random(seed)

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, TokenUsage]:
        verdict = EvalVerdict.FAIL if self._draws.random() < 0.5 else EvalVerdict.PASS
        return _judgment(output_schema, verdict)


class SilentJudge:
    """Every case stays unjudged, which is how a missing verdict reaches the report."""

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, TokenUsage]:
        raise ProviderRefusal("fault injection: the judge refuses every case", _NO_USAGE)


def _judgment[T: BaseModel](output_schema: type[T], verdict: EvalVerdict) -> tuple[T, TokenUsage]:
    # The judge role is asked for a Judgment and nothing else.
    if output_schema is not Judgment:
        raise TypeError(f"a faulty judge answers Judgment only, asked {output_schema.__name__}")
    judgment = Judgment(
        verdict=verdict, justification="fault injection: fixed verdict", severity=Severity.LOW
    )
    return cast(T, judgment), _NO_USAGE


class CategoryDroppingGenerator:
    """Drops one category from every test case batch, completions included, and from every
    chain plan, since a chain verdict also fills its cell.
    """

    def __init__(self, inner: LLMPort, category: AuditCategory) -> None:
        self._inner = inner
        self._category = category

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, TokenUsage]:
        answer, usage = await self._inner.generate_structured(prompt, output_schema)
        if isinstance(answer, TestCaseBatch):
            kept = [case for case in answer.cases if case.category != self._category]
            return cast(T, TestCaseBatch(cases=kept)), usage
        if isinstance(answer, ChainPlanBatch):
            kept = [goal for goal in answer.chains if goal.category != self._category]
            return cast(T, ChainPlanBatch(chains=kept)), usage
        return answer, usage


class ChainRefusingModel:
    """The provider refuses every chain step: planning, observation and next step."""

    def __init__(self, inner: LLMPort) -> None:
        self._inner = inner

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, TokenUsage]:
        if output_schema in _CHAIN_SCHEMAS:
            raise ProviderRefusal("fault injection: the provider refuses chain steps", _NO_USAGE)
        return await self._inner.generate_structured(prompt, output_schema)


def lose_detections(verdicts: VerdictMap, seed: int, audit_index: int) -> VerdictMap:
    """Each FAIL cell turns PASS with probability 0.5, drawn afresh at every audit.

    The draw is keyed on the cell, not on a case, so a cell with k FAIL cases is lost with
    probability 0.5 whatever k. Replays count as audits, so a replay does not reproduce the
    loss of its run by construction.
    """
    return {
        cell: EvalVerdict.PASS
        if verdict == EvalVerdict.FAIL and _loses(seed, audit_index, cell_key(cell))
        else verdict
        for cell, verdict in verdicts.items()
    }


def _loses(seed: int, audit_index: int, key: str) -> bool:
    return random.Random(f"{seed}/{audit_index}/{key}").random() < 0.5
