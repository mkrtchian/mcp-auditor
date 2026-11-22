from mcp_auditor.domain.models import AttackContext, ChainPlanBatch, StepObservation
from mcp_auditor.domain.ports import ModelCallMissed
from tests.fakes import FakeLLM
from tests.unit.auditor.support.graph_builders import a_chain_goal, a_complete_batch, a_judgment
from tests.unit.auditor.support.model_failures import a_provider_refusal


def a_fake_llm_failing_the_first_of_two_judgments(failure: ModelCallMissed) -> FakeLLM:
    return FakeLLM([a_complete_batch(2), failure, a_judgment(), AttackContext()])


def a_fake_llm_failing_the_first_tool_generation(
    failure: ModelCallMissed, cases_per_tool: int
) -> FakeLLM:
    judgments = [a_judgment() for _ in range(cases_per_tool)]
    first_tool = [failure, AttackContext()]
    second_tool = [a_complete_batch(cases_per_tool), *judgments, AttackContext()]
    return FakeLLM([*first_tool, *second_tool])


def a_fake_llm_refusing_the_chain_planning() -> FakeLLM:
    return FakeLLM([a_complete_batch(1), a_judgment(), a_provider_refusal(), AttackContext()])


def a_fake_llm_failing_the_first_chain_observation(failure: ModelCallMissed) -> FakeLLM:
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("first chain"), a_chain_goal("second chain")])
    stop_obs = StepObservation(observation="dead end", should_continue=False)
    first_chain = [failure, a_judgment()]
    second_chain = [stop_obs, a_judgment()]
    single_step = [a_complete_batch(1), a_judgment()]
    return FakeLLM([*single_step, chain_plan, *first_chain, *second_chain, AttackContext()])


def a_fake_llm_refusing_the_chain_step_planning() -> FakeLLM:
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("probe then exploit")])
    continue_obs = StepObservation(observation="promising", should_continue=True)
    chain = [chain_plan, continue_obs, a_provider_refusal(), a_judgment()]
    return FakeLLM([a_complete_batch(1), a_judgment(), *chain, AttackContext()])
