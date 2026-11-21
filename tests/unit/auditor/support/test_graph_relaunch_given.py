from mcp_auditor.domain import (
    AttackContext,
    ChainPlanBatch,
    StepObservation,
    ToolDefinition,
    ToolResponse,
)
from tests.fakes import FakeLLM, FakeMCPClient
from tests.fakes.mcp_client import a_lost_connection_response, a_timeout_response
from tests.unit.auditor.support.graph_builders import (
    a_chain_goal,
    a_complete_batch,
    a_judgment,
    a_payload,
)


def a_server_timing_out_on(tools: list[ToolDefinition], tool_name: str) -> FakeMCPClient:
    return FakeMCPClient(tools, {tool_name: a_timeout_response()})


def a_server_dying_on_its_first_chain_step(tool: ToolDefinition) -> FakeMCPClient:
    responses = [
        ToolResponse(content="ok"),
        a_lost_connection_response(),
        ToolResponse(content="ok"),
    ]
    return FakeMCPClient([tool], {tool.name: responses})


def a_server_going_down_on_its_second_chain_step(tool: ToolDefinition) -> FakeMCPClient:
    """The case and the first chain step are answered, the second step loses the connection and
    the relaunch fails."""
    responses = [
        ToolResponse(content="ok"),
        ToolResponse(content="ok"),
        a_lost_connection_response(),
    ]
    return FakeMCPClient([tool], {tool.name: responses}, relaunch_answers=(False,))


def a_fake_llm_for_a_stopped_tool_then_a_tool_with_a_chain(num_cases: int) -> FakeLLM:
    judgments = [a_judgment() for _ in range(num_cases)]
    stopped_tool = [a_complete_batch(num_cases), *judgments, AttackContext()]
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("probe then exploit")])
    stop_obs = StepObservation(observation="dead end", should_continue=False)
    chain = [chain_plan, stop_obs, a_judgment()]
    next_tool = [a_complete_batch(num_cases), *judgments, *chain, AttackContext()]
    return FakeLLM([*stopped_tool, *next_tool])


def a_fake_llm_for_a_tool_whose_server_goes_down(num_cases: int) -> FakeLLM:
    """Only the case whose call lost the connection is judged: the others are not sent."""
    return FakeLLM([a_complete_batch(num_cases), a_judgment(), AttackContext()])


def a_fake_llm_for_a_chain_cut_by_a_relaunch() -> FakeLLM:
    """The step cut by the relaunch is judged with no observation."""
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("probe then exploit")])
    return FakeLLM([a_complete_batch(1), a_judgment(), chain_plan, a_judgment(), AttackContext()])


def a_fake_llm_for_two_chains_whose_server_goes_down_on_the_second_step() -> FakeLLM:
    """The step that took the server down is judged with no observation, and the second chain
    sends nothing."""
    chain_plan = ChainPlanBatch(chains=[a_chain_goal("probe then exploit"), a_chain_goal("next")])
    continue_obs = StepObservation(observation="promising", should_continue=True)
    chain = [chain_plan, continue_obs, a_payload(), a_judgment()]
    return FakeLLM([a_complete_batch(1), a_judgment(), *chain, AttackContext()])
