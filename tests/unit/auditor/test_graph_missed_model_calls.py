import pytest

import tests.unit.auditor.support.test_graph_missed_model_calls_given as given
import tests.unit.auditor.support.test_graph_missed_model_calls_then as then
from mcp_auditor.domain.model_calls import MissedCallCause, ModelCallKind
from tests.fakes import FakeLLM, FakeMCPClient
from tests.fakes.llm import FAKE_USAGE
from tests.unit.auditor.support.graph_builders import (
    a_dry_run_graph,
    a_graph,
    a_tool,
    an_initial_state,
)
from tests.unit.auditor.support.graph_results import (
    report_has_a_gap_of,
    report_has_cases,
    report_has_judged_chains,
    report_has_no_chains,
    tool_report_at,
)


@pytest.mark.parametrize("cause", list(given.MODEL_FAILURES))
async def test_a_missed_judgment_does_not_stop_the_audit(cause: MissedCallCause):
    failure = given.MODEL_FAILURES[cause]()
    fake_llm = given.a_fake_llm_failing_the_first_of_two_judgments(failure)
    graph = a_graph(fake_llm, FakeMCPClient([a_tool(name="get_user")]))
    state = an_initial_state(test_budget=2)

    result = await graph.ainvoke(state)

    report = tool_report_at(result, 0)
    assert [case.judge_result is None for case in report.cases] == [True, False]
    then.audit_report_misses_one_call(result, "get_user", ModelCallKind.JUDGMENT, cause)
    assert result["audit_report"].provider_usage == fake_llm.total_usage
    assert result["audit_report"].judge_usage == failure.usage.add(FAKE_USAGE)


@pytest.mark.parametrize("cause", list(given.MODEL_FAILURES))
async def test_a_missed_first_generation_leaves_its_tool_untested_and_audits_the_next(
    cause: MissedCallCause,
):
    tools = [a_tool(name="get_user"), a_tool(name="list_users")]
    failure = given.MODEL_FAILURES[cause]()
    fake_llm = given.a_fake_llm_failing_the_first_tool_generation(failure, cases_per_tool=2)
    graph = a_graph(fake_llm, FakeMCPClient(tools))
    state = an_initial_state(test_budget=2)

    result = await graph.ainvoke(state)

    first = tool_report_at(result, 0)
    report_has_cases(first, 0)
    report_has_a_gap_of(first, requested=2, received=0)
    report_has_cases(tool_report_at(result, 1), 2)
    then.audit_report_misses_one_call(result, "get_user", ModelCallKind.TEST_GENERATION, cause)
    assert result["audit_report"].provider_usage == fake_llm.total_usage


async def test_a_dry_run_with_a_refused_generation_carries_the_missed_model_call():
    fake_llm = FakeLLM([given.a_provider_refusal()])
    graph = a_dry_run_graph(fake_llm, FakeMCPClient([a_tool(name="get_user")]))
    state = an_initial_state(test_budget=3)

    result = await graph.ainvoke(state)

    report_has_a_gap_of(result["tool_reports"][0], requested=3, received=0)
    then.state_has_missed_calls(result, [("get_user", ModelCallKind.TEST_GENERATION)])


async def test_a_refused_chain_planning_leaves_the_tool_without_chains():
    fake_llm = given.a_fake_llm_refusing_the_chain_planning()
    graph = a_graph(fake_llm, FakeMCPClient([a_tool(name="get_user")]))
    state = an_initial_state(test_budget=1, chain_budget=1)

    result = await graph.ainvoke(state)

    report_has_no_chains(tool_report_at(result, 0))
    then.audit_report_has_missed_calls(result, [("get_user", ModelCallKind.CHAIN_PLANNING)])


@pytest.mark.parametrize("cause", list(given.MODEL_FAILURES))
async def test_a_missed_observation_judges_its_chain_and_the_next_chain_runs(
    cause: MissedCallCause,
):
    fake_llm = given.a_fake_llm_failing_the_first_chain_observation(given.MODEL_FAILURES[cause]())
    graph = a_graph(fake_llm, FakeMCPClient([a_tool(name="get_user")]))
    state = an_initial_state(test_budget=1, chain_budget=2)

    result = await graph.ainvoke(state)

    report_has_judged_chains(tool_report_at(result, 0), 2)
    then.audit_report_misses_one_call(
        result, "get_user", ModelCallKind.CHAIN_STEP_OBSERVATION, cause
    )


async def test_a_chain_step_planning_refusal_judges_the_chain_with_the_steps_it_has():
    fake_llm = given.a_fake_llm_refusing_the_chain_step_planning()
    fake_mcp_client = FakeMCPClient([a_tool(name="get_user")])
    graph = a_graph(fake_llm, fake_mcp_client)
    state = an_initial_state(test_budget=1, chain_budget=1, max_chain_steps=3)

    result = await graph.ainvoke(state)

    report = tool_report_at(result, 0)
    report_has_judged_chains(report, 1)
    assert len(report.chains[0].steps) == 1
    then.audit_report_has_missed_calls(result, [("get_user", ModelCallKind.CHAIN_STEP_PLANNING)])
