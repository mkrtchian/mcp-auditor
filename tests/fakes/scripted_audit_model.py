from collections.abc import Callable
from typing import cast

from pydantic import BaseModel

from mcp_auditor.domain.models import (
    AttackContext,
    AuditCategory,
    AuditPayload,
    ChainGoal,
    ChainPlanBatch,
    ProviderUsage,
    StepObservation,
    TestCaseBatch,
)

_NO_USAGE = ProviderUsage()
# `build_attack_generation_prompt` lists the categories right under this line, up to a blank
# line. The category guidance further down also starts lines with `- info_leakage:`.
_CATEGORY_LIST_HEADER = "Distribute test cases across these attack categories:\n"


class ScriptedAuditModel:
    """The generator, answering by output schema whatever the order of the calls."""

    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]:
        answer = _ANSWERS.get(output_schema)
        if answer is None:
            raise TypeError(f"the scripted model does not answer {output_schema.__name__}")
        return cast(T, answer(prompt)), _NO_USAGE


def _one_case_per_requested_category(prompt: str) -> TestCaseBatch:
    return TestCaseBatch(cases=[_empty_payload(category) for category in _categories_of(prompt)])


def _categories_of(prompt: str) -> list[AuditCategory]:
    _, header, rest = prompt.partition(_CATEGORY_LIST_HEADER)
    if not header:
        raise ValueError(f"no category list in the attack prompt:\n{prompt}")
    category_list = rest.split("\n\n", 1)[0]
    return [AuditCategory(line.removeprefix("- ")) for line in category_list.splitlines()]


def _one_info_leakage_chain(prompt: str) -> ChainPlanBatch:
    goal = ChainGoal(
        description="scripted chain",
        category=AuditCategory.INFO_LEAKAGE,
        first_step=_empty_payload(AuditCategory.INFO_LEAKAGE),
    )
    return ChainPlanBatch(chains=[goal])


def _empty_payload(category: AuditCategory) -> AuditPayload:
    return AuditPayload(category=category, description="scripted case", arguments={})


_ANSWERS: dict[type[BaseModel], Callable[[str], BaseModel]] = {
    TestCaseBatch: _one_case_per_requested_category,
    AttackContext: lambda _: AttackContext(),
    ChainPlanBatch: _one_info_leakage_chain,
    StepObservation: lambda _: StepObservation(observation="scripted", should_continue=False),
    AuditPayload: lambda _: _empty_payload(AuditCategory.INFO_LEAKAGE),
}
