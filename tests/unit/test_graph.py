import pytest

import tests.unit.support.test_graph_given as given
import tests.unit.support.test_graph_then as then
from tests.fakes import FakeLLM, FakeMCPClient


@pytest.mark.asyncio
async def test_single_tool_single_test_case():
    tool = given.a_tool(name="get_user")
    fake_llm = given.a_fake_llm_for_single_tool_audit(tool_name="get_user", num_cases=1)
    fake_mcp = FakeMCPClient([tool])
    graph = given.a_graph(fake_llm, fake_mcp)
    state = given.an_initial_state(test_budget=5)

    result = await given.invoke_graph(graph, state)

    then.has_tool_reports(result, 1)
    report = then.tool_report_at(result, 0)
    then.report_has_cases(report, 1)
    then.report_is_for_tool(report, "get_user")


@pytest.mark.asyncio
async def test_two_tools_two_cases_each():
    tool_a = given.a_tool(name="get_user")
    tool_b = given.a_tool(name="delete_user")
    fake_llm = given.a_fake_llm_for_multi_tool_audit([("get_user", 2), ("delete_user", 2)])
    fake_mcp = FakeMCPClient([tool_a, tool_b])
    graph = given.a_graph(fake_llm, fake_mcp)
    state = given.an_initial_state(test_budget=5)

    result = await given.invoke_graph(graph, state)

    then.has_tool_reports(result, 2)
    first = then.tool_report_at(result, 0)
    then.report_has_cases(first, 2)
    then.report_is_for_tool(first, "get_user")
    second = then.tool_report_at(result, 1)
    then.report_has_cases(second, 2)
    then.report_is_for_tool(second, "delete_user")


@pytest.mark.asyncio
async def test_empty_tool_list():
    fake_llm = FakeLLM([])
    fake_mcp = FakeMCPClient([])
    graph = given.a_graph(fake_llm, fake_mcp)
    state = given.an_initial_state(test_budget=5)

    result = await given.invoke_graph(graph, state)

    then.has_tool_reports(result, 0)


@pytest.mark.asyncio
async def test_token_usage_accumulated():
    tool = given.a_tool(name="get_user")
    # 2 test cases = 1 generate + 2 judge + 1 extract = 4 LLM calls
    fake_llm = given.a_fake_llm_for_single_tool_audit(tool_name="get_user", num_cases=2)
    fake_mcp = FakeMCPClient([tool])
    graph = given.a_graph(fake_llm, fake_mcp)
    state = given.an_initial_state(test_budget=5)

    result = await given.invoke_graph(graph, state)

    usage = result["audit_report"].token_usage
    assert usage.input_tokens == 40  # 4 calls * 10
    assert usage.output_tokens == 20  # 4 calls * 5


@pytest.mark.asyncio
async def test_attack_context_populated_after_audit():
    from mcp_auditor.domain import AttackContext

    tool = given.a_tool(name="get_user")
    fake_llm = given.a_fake_llm_for_single_tool_audit(
        tool_name="get_user",
        num_cases=1,
        extraction_response=AttackContext(db_engine="sqlite"),
    )
    fake_mcp = FakeMCPClient([tool])
    graph = given.a_graph(fake_llm, fake_mcp)
    state = given.an_initial_state(test_budget=5)

    result = await given.invoke_graph(graph, state)

    then.attack_context_is_non_empty(result)
    assert result["attack_context"].db_engine == "sqlite"
