from pydantic import BaseModel

from mcp_auditor.domain.models import (
    AttackContext,
    AuditCategory,
    ChainPlanBatch,
    Judgment,
    ProviderUsage,
    StepObservation,
    TestCaseBatch,
)
from tests.fakes import FakeLLM
from tests.fakes.llm import Billing, flat_billing
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


def a_fake_llm_for_single_tool_with_chain(
    num_cases: int = 1, billing: Billing = flat_billing
) -> FakeLLM:
    batch = a_complete_batch(num_cases)
    judgments = [a_judgment() for _ in range(num_cases)]
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("probe then exploit")])
    step_obs = StepObservation(observation="dead end", should_continue=False)
    chain_judgment = a_judgment()
    context = AttackContext()
    return FakeLLM(
        [batch, *judgments, chain_plan, step_obs, chain_judgment, context], billing=billing
    )


def billing_judge_apart(judge_usage: ProviderUsage, generator_usage: ProviderUsage) -> Billing:
    def bill(output_schema: type[BaseModel], call_index: int) -> ProviderUsage:
        return judge_usage if output_schema is Judgment else generator_usage

    return bill


def billing_each_call_apart(output_schema: type[BaseModel], call_index: int) -> ProviderUsage:
    """Bills each call a usage of its own, so a sum names the calls it covers."""
    return ProviderUsage(input_tokens=2**call_index, output_tokens=1)


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
