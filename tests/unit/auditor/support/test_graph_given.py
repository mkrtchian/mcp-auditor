from typing import override

from pydantic import BaseModel

from mcp_auditor.domain import (
    AttackContext,
    AuditCategory,
    ChainPlanBatch,
    Judgment,
    ProviderUsage,
    StepObservation,
    TestCaseBatch,
)
from tests.fakes import FakeLLM
from tests.unit.auditor.support.graph_builders import (
    a_chain_goal,
    a_complete_batch,
    a_judgment,
    a_payload,
)


def a_fake_llm_for_destructive_and_safe_case() -> FakeLLM:
    batch = TestCaseBatch(
        cases=[
            a_payload(arguments={"command": "rm -rf /"}),
            a_payload(category=AuditCategory.INFO_LEAKAGE, arguments={"input": "malicious"}),
        ]
    )
    return FakeLLM([batch, a_judgment(), AttackContext()])


def a_fake_llm_for_two_tool_audit_extracting(
    first_answer: AttackContext, second_answer: AttackContext
) -> FakeLLM:
    first_tool = [a_complete_batch(1), a_judgment(), first_answer]
    return FakeLLM([*first_tool, a_complete_batch(1), a_judgment(), second_answer])


def a_fake_llm_whose_first_tool_batch_stays_short(cases_per_tool: int) -> FakeLLM:
    short = a_complete_batch(cases_per_tool - 1)
    short_judgments = [a_judgment() for _ in short.cases]
    complete = a_complete_batch(cases_per_tool)
    complete_judgments = [a_judgment() for _ in complete.cases]
    first_tool = [short, short, a_complete_batch(1), *short_judgments, AttackContext()]
    second_tool = [complete, *complete_judgments, AttackContext()]
    return FakeLLM([*first_tool, *second_tool])


def a_fake_dry_run_llm_whose_batch_stays_short(budget: int) -> FakeLLM:
    short = a_complete_batch(budget - 1)
    return FakeLLM([short, short, a_complete_batch(1)])


class PerRoleBillingLLM(FakeLLM):
    """Bills judge calls (the Judgment schema) apart from generator calls."""

    def __init__(
        self,
        responses: list[BaseModel],
        judge_usage: ProviderUsage,
        generator_usage: ProviderUsage,
    ):
        super().__init__(responses)
        self._judge_usage = judge_usage
        self._generator_usage = generator_usage

    @override
    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]:
        self.prompts.append(prompt)
        response = self._responses.popleft()
        if not isinstance(response, output_schema):
            raise TypeError(f"Expected {output_schema.__name__}, got {type(response).__name__}")
        usage = self._judge_usage if output_schema is Judgment else self._generator_usage
        self.total_usage = self.total_usage.add(usage)
        return response, usage  # type: ignore[return-value]


def a_fake_llm_billing_judge_apart(
    judge_usage: ProviderUsage, generator_usage: ProviderUsage, num_cases: int = 1
) -> PerRoleBillingLLM:
    batch = a_complete_batch(num_cases)
    judgments = [a_judgment() for _ in range(num_cases)]
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("probe then exploit")])
    step_obs = StepObservation(observation="dead end", should_continue=False)
    responses: list[BaseModel] = [batch, *judgments, chain_plan, step_obs, a_judgment()]
    responses.append(AttackContext())
    return PerRoleBillingLLM(responses, judge_usage, generator_usage)


class PerCallBillingLLM(FakeLLM):
    """Bills each call a usage of its own, so a sum names the calls it covers."""

    def __init__(self, responses: list[BaseModel]):
        super().__init__(responses)
        self.billed: list[ProviderUsage] = []

    @override
    async def generate_structured[T: BaseModel](
        self, prompt: str, output_schema: type[T]
    ) -> tuple[T, ProviderUsage]:
        self.prompts.append(prompt)
        response = self._responses.popleft()
        if not isinstance(response, output_schema):
            raise TypeError(f"Expected {output_schema.__name__}, got {type(response).__name__}")
        usage = ProviderUsage(input_tokens=2 ** len(self.billed), output_tokens=1)
        self.billed.append(usage)
        self.total_usage = self.total_usage.add(usage)
        return response, usage  # type: ignore[return-value]


# Chain planning, two observations, one step planning and the chain judgment.
TWO_STEP_CHAIN_CALLS = slice(2, 7)


def a_fake_llm_billing_each_call_apart_with_a_two_step_chain() -> PerCallBillingLLM:
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("probe then exploit")])
    continue_obs = StepObservation(observation="promising", should_continue=True)
    stop_obs = StepObservation(observation="dead end", should_continue=False)
    chain = [chain_plan, continue_obs, a_payload(), stop_obs, a_judgment()]
    return PerCallBillingLLM([a_complete_batch(1), a_judgment(), *chain, AttackContext()])


def a_fake_llm_for_single_tool_with_chain(num_cases: int = 1) -> FakeLLM:
    batch = a_complete_batch(num_cases)
    judgments = [a_judgment() for _ in range(num_cases)]
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("probe then exploit")])
    step_obs = StepObservation(observation="dead end", should_continue=False)
    chain_judgment = a_judgment()
    context = AttackContext()
    return FakeLLM([batch, *judgments, chain_plan, step_obs, chain_judgment, context])


def a_fake_llm_for_single_tool_with_two_chains(num_cases: int = 1) -> FakeLLM:
    batch = a_complete_batch(num_cases)
    judgments = [a_judgment() for _ in range(num_cases)]
    chain_plan = ChainPlanBatch(
        chains=[
            a_chain_goal("first chain"),
            a_chain_goal("second chain", category=AuditCategory.INFO_LEAKAGE),
        ]
    )
    stop_obs = StepObservation(observation="dead end", should_continue=False)
    context = AttackContext()
    return FakeLLM(
        [batch, *judgments, chain_plan, stop_obs, a_judgment(), stop_obs, a_judgment(), context]
    )
