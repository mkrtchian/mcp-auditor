from collections.abc import Callable

import pytest
from langgraph.checkpoint.memory import MemorySaver  # type: ignore[import-untyped]

import tests.unit.auditor.support.test_graph_given as given
import tests.unit.auditor.support.test_graph_then as then
from mcp_auditor.domain import AttackContext, ProviderUsage
from mcp_auditor.graph.prompts import REDACTION_NOTICE
from tests.fakes import FakeLLM, FakeMCPClient
from tests.unit.auditor.support.graph_builders import (
    a_dry_run_graph,
    a_fake_llm_for_multi_tool_audit,
    a_fake_llm_for_single_tool_audit,
    a_fake_llm_for_single_tool_with_a_two_step_chain,
    a_graph,
    a_graph_with_checkpointer,
    a_redacting_graph,
    a_server_echoing,
    a_tool,
    an_initial_state,
    invoke_graph,
    invoke_graph_with_config,
)
from tests.unit.auditor.support.graph_results import (
    report_has_a_gap_of,
    report_has_cases,
    report_has_judged_chains,
    report_has_no_chains,
    report_has_no_gap,
    tool_report_at,
)


async def test_single_tool_single_test_case():
    tool = a_tool(name="get_user")
    fake_llm = a_fake_llm_for_single_tool_audit(num_cases=1)
    fake_mcp_client = FakeMCPClient([tool])
    graph = a_graph(fake_llm, fake_mcp_client)
    state = an_initial_state(test_budget=1)

    result = await invoke_graph(graph, state)

    then.has_tool_reports(result, 1)
    report = tool_report_at(result, 0)
    report_has_cases(report, 1)
    then.report_is_for_tool(report, "get_user")


async def test_two_tools_two_cases_each():
    tool_a = a_tool(name="get_user")
    tool_b = a_tool(name="delete_user")
    fake_llm = a_fake_llm_for_multi_tool_audit([2, 2])
    fake_mcp_client = FakeMCPClient([tool_a, tool_b])
    graph = a_graph(fake_llm, fake_mcp_client)
    state = an_initial_state(test_budget=2)

    result = await invoke_graph(graph, state)

    then.has_tool_reports(result, 2)
    first = tool_report_at(result, 0)
    report_has_cases(first, 2)
    then.report_is_for_tool(first, "get_user")
    second = tool_report_at(result, 1)
    report_has_cases(second, 2)
    then.report_is_for_tool(second, "delete_user")


async def test_empty_tool_list():
    fake_llm = FakeLLM([])
    fake_mcp_client = FakeMCPClient([])
    graph = a_graph(fake_llm, fake_mcp_client)
    state = an_initial_state(test_budget=1)

    result = await invoke_graph(graph, state)

    then.has_tool_reports(result, 0)


async def test_provider_usage_accumulated():
    tool = a_tool(name="get_user")
    fake_llm = a_fake_llm_for_single_tool_audit(num_cases=2)
    fake_mcp_client = FakeMCPClient([tool])
    graph = a_graph(fake_llm, fake_mcp_client)
    state = an_initial_state(test_budget=2)

    result = await invoke_graph(graph, state)

    usage = result["audit_report"].provider_usage
    assert usage.input_tokens > 0
    assert usage == fake_llm.total_usage


async def test_attack_context_populated_after_audit():
    tool = a_tool(name="get_user")
    fake_llm = a_fake_llm_for_single_tool_audit(
        num_cases=1,
        extraction_response=AttackContext(db_engine="sqlite"),
    )
    fake_mcp_client = FakeMCPClient([tool])
    graph = a_graph(fake_llm, fake_mcp_client)
    state = an_initial_state(test_budget=1)

    result = await invoke_graph(graph, state)

    assert result["attack_context"].db_engine == "sqlite"


async def test_an_item_reported_on_one_tool_survives_a_later_answer_that_omits_it():
    tools = [a_tool(name="get_user"), a_tool(name="delete_user")]
    fake_llm = given.a_fake_llm_for_two_tool_audit_extracting(
        AttackContext(exposed_internals=["users table"]),
        AttackContext(exposed_internals=["/srv/app/config.yaml"]),
    )
    graph = a_graph(fake_llm, FakeMCPClient(tools))
    state = an_initial_state(test_budget=1)

    result = await invoke_graph(graph, state)

    assert result["attack_context"].exposed_internals == ["users table", "/srv/app/config.yaml"]


async def test_chain_budget_zero_skips_chains():
    tool = a_tool(name="get_user")
    fake_llm = a_fake_llm_for_single_tool_audit(num_cases=1)
    fake_mcp_client = FakeMCPClient([tool])
    graph = a_graph(fake_llm, fake_mcp_client)
    state = an_initial_state(test_budget=1, chain_budget=0, max_chain_steps=3)

    result = await invoke_graph(graph, state)

    then.has_tool_reports(result, 1)
    report_has_no_chains(tool_report_at(result, 0))


@pytest.mark.parametrize(
    ("chain_budget", "a_fake_llm"),
    [
        (1, given.a_fake_llm_for_single_tool_with_chain),
        (2, given.a_fake_llm_for_single_tool_with_two_chains),
    ],
)
async def test_the_chain_budget_sets_the_number_of_judged_chains(
    chain_budget: int, a_fake_llm: Callable[..., FakeLLM]
):
    tool = a_tool(name="get_user")
    fake_llm = a_fake_llm(num_cases=1)
    fake_mcp_client = FakeMCPClient([tool])
    graph = a_graph(fake_llm, fake_mcp_client)
    state = an_initial_state(test_budget=1, chain_budget=chain_budget, max_chain_steps=3)

    result = await invoke_graph(graph, state)

    then.has_tool_reports(result, 1)
    report_has_judged_chains(tool_report_at(result, 0), chain_budget)


async def test_a_redacting_server_puts_the_notice_in_every_prompt_and_its_value_in_none():
    tool = a_tool(name="get_user")
    fake_llm = a_fake_llm_for_single_tool_with_a_two_step_chain()
    server = a_server_echoing(tool, "token=s3cr3t-value")
    graph = a_redacting_graph(fake_llm, server, {"TOKEN": "s3cr3t-value"})
    state = an_initial_state(test_budget=1, chain_budget=1, max_chain_steps=3)

    await invoke_graph(graph, state)

    then.every_prompt_has_the_redaction_notice(fake_llm, expected_prompts=8)
    then.no_prompt_holds(fake_llm, "s3cr3t-value")


async def test_a_server_without_redaction_puts_the_notice_in_no_prompt():
    tool = a_tool(name="get_user")
    fake_llm = a_fake_llm_for_single_tool_with_a_two_step_chain()
    graph = a_graph(fake_llm, a_server_echoing(tool, "token=s3cr3t-value"))
    state = an_initial_state(test_budget=1, chain_budget=1, max_chain_steps=3)

    await invoke_graph(graph, state)

    then.no_prompt_holds(fake_llm, REDACTION_NOTICE)


async def test_the_checkpointer_round_trips_the_chain_state():
    tool = a_tool(name="get_user")
    fake_llm = given.a_fake_llm_for_single_tool_with_chain(num_cases=1)
    fake_mcp_client = FakeMCPClient([tool])
    graph = a_graph_with_checkpointer(fake_llm, fake_mcp_client, MemorySaver())
    state = an_initial_state(test_budget=1, chain_budget=1, max_chain_steps=3)
    config = {"configurable": {"thread_id": "round-trip"}}

    await invoke_graph_with_config(graph, state, config)
    stored = (await graph.aget_state({"configurable": {"thread_id": "round-trip"}})).values

    report_has_judged_chains(stored["audit_report"].tool_reports[0], 1)


async def test_destructive_payload_is_blocked_and_never_sent():
    tool = a_tool(name="run_command")
    fake_llm = given.a_fake_llm_for_destructive_and_safe_case()
    fake_mcp_client = FakeMCPClient([tool])
    graph = a_graph(fake_llm, fake_mcp_client)
    state = an_initial_state(test_budget=2)

    result = await invoke_graph(graph, state)

    report = tool_report_at(result, 0)
    report_has_cases(report, 2)
    then.one_case_blocked_unjudged_and_not_called(report, fake_mcp_client)


async def test_a_batch_still_short_after_retry_is_flagged_on_its_tool_only():
    tools = [a_tool(name="get_user"), a_tool(name="list_users")]
    fake_llm = given.a_fake_llm_whose_first_tool_batch_stays_short(cases_per_tool=2)
    graph = a_graph(fake_llm, FakeMCPClient(tools))
    state = an_initial_state(test_budget=2)

    result = await invoke_graph(graph, state)

    report_has_a_gap_of(tool_report_at(result, 0), requested=2, received=1)
    report_has_no_gap(tool_report_at(result, 1))


async def test_a_dry_run_carries_the_coverage_gap_to_its_tool_report():
    fake_llm = given.a_fake_dry_run_llm_whose_batch_stays_short(budget=3)
    graph = a_dry_run_graph(fake_llm, FakeMCPClient([a_tool(name="get_user")]))
    state = an_initial_state(test_budget=3)

    result = await invoke_graph(graph, state)

    report_has_a_gap_of(result["tool_reports"][0], requested=3, received=2)


async def test_the_report_splits_judge_usage_from_generator_usage():
    judge_usage = ProviderUsage(input_tokens=3, output_tokens=2)
    generator_usage = ProviderUsage(input_tokens=11, output_tokens=7)
    fake_llm = given.a_fake_llm_billing_judge_apart(judge_usage, generator_usage)
    graph = a_graph(fake_llm, FakeMCPClient([a_tool(name="get_user")]))
    state = an_initial_state(test_budget=1, chain_budget=1)

    result = await invoke_graph(graph, state)

    then.report_splits_usage(
        result,
        judge_calls=2,
        judge_usage=judge_usage,
        generator_calls=4,
        generator_usage=generator_usage,
    )
    assert result["audit_report"].provider_usage == fake_llm.total_usage


async def test_the_report_splits_chain_usage_from_single_step_usage():
    fake_llm = given.a_fake_llm_billing_each_call_apart_with_a_two_step_chain()
    graph = a_graph(fake_llm, FakeMCPClient([a_tool(name="get_user")]))
    state = an_initial_state(test_budget=1, chain_budget=1)

    result = await invoke_graph(graph, state)

    then.report_bills_to_chains(result, fake_llm.billed[given.TWO_STEP_CHAIN_CALLS])
    assert result["audit_report"].provider_usage == fake_llm.total_usage


async def test_an_audit_without_chains_reports_no_chain_usage():
    fake_llm = a_fake_llm_for_single_tool_audit(num_cases=2)
    graph = a_graph(fake_llm, FakeMCPClient([a_tool(name="get_user")]))
    state = an_initial_state(test_budget=2)

    result = await invoke_graph(graph, state)

    report = result["audit_report"]
    assert report.chain_usage == ProviderUsage()
    assert report.single_step_usage == report.provider_usage
