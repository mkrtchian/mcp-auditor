from mcp_auditor.domain import AttackContext, ChainPlanBatch, ProviderUsage, StepObservation
from mcp_auditor.domain.models import MissCause
from mcp_auditor.domain.ports import (
    PromptTooLong,
    ProviderRefusal,
    ProviderThrottled,
    UnparseableOutput,
)
from tests.fakes import FakeLLM
from tests.fakes.llm import ModelFailure
from tests.unit.auditor.support.graph_builders import a_chain_goal, a_complete_batch, a_judgment


def a_fake_llm_failing_the_first_of_two_judgments(failure: ModelFailure) -> FakeLLM:
    return FakeLLM([a_complete_batch(2), failure, a_judgment(), AttackContext()])


def a_fake_llm_failing_the_first_tool_generation(
    failure: ModelFailure, cases_per_tool: int
) -> FakeLLM:
    judgments = [a_judgment() for _ in range(cases_per_tool)]
    first_tool = [failure, AttackContext()]
    second_tool = [a_complete_batch(cases_per_tool), *judgments, AttackContext()]
    return FakeLLM([*first_tool, *second_tool])


def a_fake_llm_refusing_the_chain_planning() -> FakeLLM:
    return FakeLLM([a_complete_batch(1), a_judgment(), a_provider_refusal(), AttackContext()])


def a_fake_llm_failing_the_first_chain_observation(failure: ModelFailure) -> FakeLLM:
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


def a_provider_refusal() -> ProviderRefusal:
    return ProviderRefusal("flagged by policy", ProviderUsage(input_tokens=7, output_tokens=0))


def an_unreadable_answer() -> UnparseableOutput:
    return UnparseableOutput(3, 1, ProviderUsage(input_tokens=40, output_tokens=12))


def a_provider_throttling() -> ProviderThrottled:
    return ProviderThrottled("slow down", 300.0, ProviderUsage(throttled_requests=8))


def a_prompt_too_long() -> PromptTooLong:
    return PromptTooLong(ProviderUsage(throttled_requests=2))


MODEL_FAILURES = {
    MissCause.PROVIDER_REFUSAL: a_provider_refusal,
    MissCause.UNREADABLE_ANSWER: an_unreadable_answer,
    MissCause.PROVIDER_THROTTLED: a_provider_throttling,
    MissCause.PROMPT_TOO_LONG: a_prompt_too_long,
}
