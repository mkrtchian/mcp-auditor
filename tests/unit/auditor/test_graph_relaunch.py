import tests.unit.auditor.support.test_graph_relaunch_given as given
import tests.unit.auditor.support.test_graph_relaunch_then as then
from mcp_auditor.domain.server_liveness import Relaunch, RelaunchCause, UnsentCause
from mcp_auditor.domain.server_watch import TIMEOUTS_IN_A_ROW
from tests.unit.auditor.support.graph_builders import (
    a_fake_llm_for_single_tool_audit,
    a_graph,
    a_payload,
    a_server_dying_on,
    a_tool,
    an_initial_state,
)
from tests.unit.auditor.support.graph_results import (
    report_has_cases,
    report_has_judged_chains,
    report_has_no_chains,
    report_has_no_gap,
    tool_report_at,
)


async def test_a_tool_timing_out_in_a_row_is_stopped_and_the_next_tool_is_audited():
    tools = [a_tool(name="stalls"), a_tool(name="answers")]
    fake_llm = given.a_fake_llm_for_a_stopped_tool_then_a_tool_with_a_chain(
        num_cases=TIMEOUTS_IN_A_ROW
    )
    graph = a_graph(fake_llm, given.a_server_timing_out_on(tools, "stalls"))
    state = an_initial_state(test_budget=TIMEOUTS_IN_A_ROW, chain_budget=1)

    result = await graph.ainvoke(state)

    stopped = tool_report_at(result, 0)
    report_has_no_chains(stopped)
    then.report_has_unsent_calls(stopped, cases=0, chains=1, cause=UnsentCause.TOOL_TIMING_OUT)
    next_tool = tool_report_at(result, 1)
    report_has_cases(next_tool, TIMEOUTS_IN_A_ROW)
    report_has_judged_chains(next_tool, 1)
    report_has_no_gap(next_tool)


async def test_a_server_whose_relaunch_fails_ends_the_audit_with_the_tools_left_in_gaps():
    tools = [a_tool(name="dies"), a_tool(name="second"), a_tool(name="third")]
    fake_llm = given.a_fake_llm_for_a_tool_whose_server_goes_down(num_cases=2)
    graph = a_graph(fake_llm, a_server_dying_on(tools, "dies", relaunches=False))
    state = an_initial_state(test_budget=2, chain_budget=1)

    result = await graph.ainvoke(state)

    then.report_has_unsent_calls(
        tool_report_at(result, 0), cases=1, chains=1, cause=UnsentCause.SERVER_DOWN
    )
    then.tools_left_in_server_down_gaps(result, ["second", "third"], test_budget=2, chains=1)
    assert not result["audit_report"].is_complete


async def test_a_relaunch_that_succeeds_is_reported_and_the_audit_is_complete():
    tool = a_tool(name="dies")
    fake_llm = a_fake_llm_for_single_tool_audit(num_cases=1)
    graph = a_graph(fake_llm, a_server_dying_on([tool], "dies", relaunches=True))

    result = await graph.ainvoke(an_initial_state(test_budget=1))

    assert result["audit_report"].relaunches == [
        Relaunch(
            tool_name="dies",
            arguments=a_payload().arguments,
            cause=RelaunchCause.LOST_CONNECTION,
            succeeded=True,
        )
    ]
    assert result["audit_report"].is_complete


async def test_a_chain_cut_by_a_relaunch_leaves_its_tool_with_no_gap():
    tool = a_tool(name="dies")
    fake_llm = given.a_fake_llm_for_a_chain_cut_by_a_relaunch()
    graph = a_graph(fake_llm, given.a_server_dying_on_its_first_chain_step(tool))
    state = an_initial_state(test_budget=1, chain_budget=1)

    result = await graph.ainvoke(state)

    report = tool_report_at(result, 0)
    report_has_judged_chains(report, 1)
    assert report.chains[0].cut_by_relaunch
    report_has_no_gap(report)


async def test_a_server_going_down_mid_chain_judges_the_steps_made_and_counts_the_next_chain():
    tool = a_tool(name="dies")
    fake_llm = given.a_fake_llm_for_two_chains_whose_server_goes_down_on_the_second_step()
    graph = a_graph(fake_llm, given.a_server_going_down_on_its_second_chain_step(tool))
    state = an_initial_state(test_budget=1, chain_budget=2, max_chain_steps=3)

    result = await graph.ainvoke(state)

    report = tool_report_at(result, 0)
    report_has_judged_chains(report, 1)
    assert len(report.chains[0].steps) == 2
    then.report_has_unsent_calls(report, cases=0, chains=1, cause=UnsentCause.SERVER_DOWN)
    assert not result["audit_report"].is_complete
