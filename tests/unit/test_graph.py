import pytest
from langgraph.checkpoint.memory import MemorySaver  # type: ignore[import-untyped]

import tests.unit.support.test_graph_given as given
import tests.unit.support.test_graph_then as then
from mcp_auditor.domain import AttackContext
from mcp_auditor.domain.models import AuditStep, MissCause
from mcp_auditor.graph.prompts import REDACTION_NOTICE
from tests.fakes import FakeLLM, FakeMCPClient
from tests.fakes.llm import FAKE_USAGE


@pytest.mark.asyncio
async def test_single_tool_single_test_case():
    tool = given.a_tool(name="get_user")
    fake_llm = given.a_fake_llm_for_single_tool_audit(num_cases=1)
    fake_mcp_client = FakeMCPClient([tool])
    graph = given.a_graph(fake_llm, fake_mcp_client)
    state = given.an_initial_state(test_budget=1)

    result = await given.invoke_graph(graph, state)

    then.has_tool_reports(result, 1)
    report = then.tool_report_at(result, 0)
    then.report_has_cases(report, 1)
    then.report_is_for_tool(report, "get_user")


@pytest.mark.asyncio
async def test_two_tools_two_cases_each():
    tool_a = given.a_tool(name="get_user")
    tool_b = given.a_tool(name="delete_user")
    fake_llm = given.a_fake_llm_for_multi_tool_audit([2, 2])
    fake_mcp_client = FakeMCPClient([tool_a, tool_b])
    graph = given.a_graph(fake_llm, fake_mcp_client)
    state = given.an_initial_state(test_budget=2)

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
    fake_mcp_client = FakeMCPClient([])
    graph = given.a_graph(fake_llm, fake_mcp_client)
    state = given.an_initial_state(test_budget=1)

    result = await given.invoke_graph(graph, state)

    then.has_tool_reports(result, 0)


@pytest.mark.asyncio
async def test_provider_usage_accumulated():
    tool = given.a_tool(name="get_user")
    fake_llm = given.a_fake_llm_for_single_tool_audit(num_cases=2)
    fake_mcp_client = FakeMCPClient([tool])
    graph = given.a_graph(fake_llm, fake_mcp_client)
    state = given.an_initial_state(test_budget=2)

    result = await given.invoke_graph(graph, state)

    usage = result["audit_report"].provider_usage
    assert usage.input_tokens > 0
    assert usage == fake_llm.total_usage


@pytest.mark.asyncio
async def test_attack_context_populated_after_audit():
    tool = given.a_tool(name="get_user")
    fake_llm = given.a_fake_llm_for_single_tool_audit(
        num_cases=1,
        extraction_response=AttackContext(db_engine="sqlite"),
    )
    fake_mcp_client = FakeMCPClient([tool])
    graph = given.a_graph(fake_llm, fake_mcp_client)
    state = given.an_initial_state(test_budget=1)

    result = await given.invoke_graph(graph, state)

    then.attack_context_is_non_empty(result)
    assert result["attack_context"].db_engine == "sqlite"


@pytest.mark.asyncio
async def test_chain_budget_zero_skips_chains():
    tool = given.a_tool(name="get_user")
    fake_llm = given.a_fake_llm_for_single_tool_audit(num_cases=1)
    fake_mcp_client = FakeMCPClient([tool])
    graph = given.a_graph(fake_llm, fake_mcp_client)
    state = given.an_initial_state(test_budget=1, chain_budget=0, max_chain_steps=3)

    result = await given.invoke_graph(graph, state)

    then.has_tool_reports(result, 1)
    then.report_has_no_chains(then.tool_report_at(result, 0))


@pytest.mark.asyncio
async def test_chain_budget_one_produces_chain():
    tool = given.a_tool(name="get_user")
    fake_llm = given.a_fake_llm_for_single_tool_with_chain(num_cases=1)
    fake_mcp_client = FakeMCPClient([tool])
    graph = given.a_graph(fake_llm, fake_mcp_client)
    state = given.an_initial_state(test_budget=1, chain_budget=1, max_chain_steps=3)

    result = await given.invoke_graph(graph, state)

    then.has_tool_reports(result, 1)
    report = then.tool_report_at(result, 0)
    then.report_has_chains(report, 1)
    then.chain_has_eval_result(report.chains[0])
    then.provider_usage_is_positive(result)


@pytest.mark.asyncio
async def test_a_redacting_server_puts_the_notice_in_every_prompt_and_its_value_in_none():
    tool = given.a_tool(name="get_user")
    fake_llm = given.a_fake_llm_for_single_tool_with_a_two_step_chain()
    server = given.a_server_echoing(tool, "token=s3cr3t-value")
    graph = given.a_redacting_graph(fake_llm, server, {"TOKEN": "s3cr3t-value"})
    state = given.an_initial_state(test_budget=1, chain_budget=1, max_chain_steps=3)

    await given.invoke_graph(graph, state)

    then.every_prompt_has_the_redaction_notice(fake_llm, expected_prompts=8)
    then.no_prompt_holds(fake_llm, "s3cr3t-value")


@pytest.mark.asyncio
async def test_a_server_without_redaction_puts_the_notice_in_no_prompt():
    tool = given.a_tool(name="get_user")
    fake_llm = given.a_fake_llm_for_single_tool_with_a_two_step_chain()
    graph = given.a_graph(fake_llm, given.a_server_echoing(tool, "token=s3cr3t-value"))
    state = given.an_initial_state(test_budget=1, chain_budget=1, max_chain_steps=3)

    await given.invoke_graph(graph, state)

    then.no_prompt_holds(fake_llm, REDACTION_NOTICE)


@pytest.mark.asyncio
async def test_chain_budget_two_produces_two_chains():
    tool = given.a_tool(name="get_user")
    fake_llm = given.a_fake_llm_for_single_tool_with_two_chains(num_cases=1)
    fake_mcp_client = FakeMCPClient([tool])
    graph = given.a_graph(fake_llm, fake_mcp_client)
    state = given.an_initial_state(test_budget=1, chain_budget=2, max_chain_steps=3)

    result = await given.invoke_graph(graph, state)

    then.has_tool_reports(result, 1)
    report = then.tool_report_at(result, 0)
    then.report_has_chains(report, 2)
    then.chain_has_eval_result(report.chains[0])
    then.chain_has_eval_result(report.chains[1])


@pytest.mark.asyncio
async def test_checkpointer_round_trips_nested_subgraph_state():
    tool = given.a_tool(name="get_user")
    fake_llm = given.a_fake_llm_for_single_tool_with_chain(num_cases=1)
    fake_mcp_client = FakeMCPClient([tool])
    checkpointer = MemorySaver()
    graph = given.a_graph_with_checkpointer(fake_llm, fake_mcp_client, checkpointer)
    state = given.an_initial_state(test_budget=1, chain_budget=1, max_chain_steps=3)
    config = {"configurable": {"thread_id": "round-trip"}}

    result = await given.invoke_graph_with_config(graph, state, config)

    then.has_tool_reports(result, 1)
    report = then.tool_report_at(result, 0)
    then.report_has_chains(report, 1)
    then.chain_has_eval_result(report.chains[0])


@pytest.mark.asyncio
async def test_destructive_payload_is_blocked_and_never_sent():
    tool = given.a_tool(name="run_command")
    fake_llm = given.a_fake_llm_for_destructive_and_safe_case()
    fake_mcp_client = FakeMCPClient([tool])
    graph = given.a_graph(fake_llm, fake_mcp_client)
    state = given.an_initial_state(test_budget=2)

    result = await given.invoke_graph(graph, state)

    report = then.tool_report_at(result, 0)
    then.report_has_cases(report, 2)
    blocked = [case for case in report.cases if case.blocked_reason is not None]
    assert len(blocked) == 1
    assert blocked[0].eval_result is None
    assert len([case for case in report.cases if case.eval_result is not None]) == 1
    assert len(fake_mcp_client.calls) == 1


@pytest.mark.asyncio
async def test_a_batch_still_short_after_retry_is_flagged_on_its_tool_only():
    tools = [given.a_tool(name="get_user"), given.a_tool(name="list_users")]
    fake_llm = given.a_fake_llm_whose_first_tool_batch_stays_short(cases_per_tool=2)
    graph = given.a_graph(fake_llm, FakeMCPClient(tools))
    state = given.an_initial_state(test_budget=2)

    result = await given.invoke_graph(graph, state)

    then.report_has_a_gap_of(then.tool_report_at(result, 0), requested=2, received=1)
    then.report_has_no_gap(then.tool_report_at(result, 1))


@pytest.mark.asyncio
async def test_a_dry_run_carries_the_coverage_gap_to_its_tool_report():
    fake_llm = given.a_fake_dry_run_llm_whose_batch_stays_short(budget=3)
    graph = given.a_dry_run_graph(fake_llm, FakeMCPClient([given.a_tool(name="get_user")]))
    state = given.an_initial_state(test_budget=3)

    result = await given.invoke_graph(graph, state)

    then.report_has_a_gap_of(result["tool_reports"][0], requested=3, received=2)


@pytest.mark.asyncio
@pytest.mark.parametrize("cause", list(MissCause))
async def test_a_missed_judgment_does_not_stop_the_audit(cause: MissCause):
    failure = given.MODEL_FAILURES[cause]()
    fake_llm = given.a_fake_llm_failing_the_first_of_two_judgments(failure)
    graph = given.a_graph(fake_llm, FakeMCPClient([given.a_tool(name="get_user")]))
    state = given.an_initial_state(test_budget=2)

    result = await given.invoke_graph(graph, state)

    report = then.tool_report_at(result, 0)
    assert [case.eval_result is None for case in report.cases] == [True, False]
    then.audit_report_misses_one_step(result, "get_user", AuditStep.JUDGMENT, cause)
    assert result["audit_report"].provider_usage == fake_llm.total_usage
    assert result["audit_report"].judge_usage == failure.usage.add(FAKE_USAGE)


@pytest.mark.asyncio
async def test_the_report_splits_judge_usage_from_generator_usage():
    judge_usage = given.ProviderUsage(input_tokens=3, output_tokens=2)
    generator_usage = given.ProviderUsage(input_tokens=11, output_tokens=7)
    fake_llm = given.a_fake_llm_billing_judge_apart(judge_usage, generator_usage)
    graph = given.a_graph(fake_llm, FakeMCPClient([given.a_tool(name="get_user")]))
    state = given.an_initial_state(test_budget=1, chain_budget=1)

    result = await given.invoke_graph(graph, state)

    then.report_splits_usage(
        result,
        judge_calls=2,
        judge_usage=judge_usage,
        generator_calls=4,
        generator_usage=generator_usage,
    )
    assert result["audit_report"].provider_usage == fake_llm.total_usage


@pytest.mark.asyncio
@pytest.mark.parametrize("cause", list(MissCause))
async def test_a_missed_first_generation_leaves_its_tool_untested_and_audits_the_next(
    cause: MissCause,
):
    tools = [given.a_tool(name="get_user"), given.a_tool(name="list_users")]
    failure = given.MODEL_FAILURES[cause]()
    fake_llm = given.a_fake_llm_failing_the_first_tool_generation(failure, cases_per_tool=2)
    graph = given.a_graph(fake_llm, FakeMCPClient(tools))
    state = given.an_initial_state(test_budget=2)

    result = await given.invoke_graph(graph, state)

    first = then.tool_report_at(result, 0)
    then.report_has_cases(first, 0)
    then.report_has_a_gap_of(first, requested=2, received=0)
    then.report_has_cases(then.tool_report_at(result, 1), 2)
    then.audit_report_misses_one_step(result, "get_user", AuditStep.TEST_GENERATION, cause)
    assert result["audit_report"].provider_usage == fake_llm.total_usage


@pytest.mark.asyncio
async def test_a_dry_run_with_a_refused_generation_carries_the_refused_step():
    fake_llm = FakeLLM([given.a_provider_refusal()])
    graph = given.a_dry_run_graph(fake_llm, FakeMCPClient([given.a_tool(name="get_user")]))
    state = given.an_initial_state(test_budget=3)

    result = await given.invoke_graph(graph, state)

    then.report_has_a_gap_of(result["tool_reports"][0], requested=3, received=0)
    then.state_has_missed_steps(result, [("get_user", AuditStep.TEST_GENERATION)])


@pytest.mark.asyncio
async def test_a_refused_chain_planning_leaves_the_tool_without_chains():
    fake_llm = given.a_fake_llm_refusing_the_chain_planning()
    graph = given.a_graph(fake_llm, FakeMCPClient([given.a_tool(name="get_user")]))
    state = given.an_initial_state(test_budget=1, chain_budget=1)

    result = await given.invoke_graph(graph, state)

    then.report_has_no_chains(then.tool_report_at(result, 0))
    then.audit_report_has_missed_steps(result, [("get_user", AuditStep.CHAIN_PLANNING)])


@pytest.mark.asyncio
@pytest.mark.parametrize("cause", list(MissCause))
async def test_a_missed_observation_judges_its_chain_and_the_next_chain_runs(cause: MissCause):
    fake_llm = given.a_fake_llm_failing_the_first_chain_observation(given.MODEL_FAILURES[cause]())
    graph = given.a_graph(fake_llm, FakeMCPClient([given.a_tool(name="get_user")]))
    state = given.an_initial_state(test_budget=1, chain_budget=2)

    result = await given.invoke_graph(graph, state)

    report = then.tool_report_at(result, 0)
    then.report_has_chains(report, 2)
    then.chain_has_eval_result(report.chains[0])
    then.chain_has_eval_result(report.chains[1])
    then.audit_report_misses_one_step(result, "get_user", AuditStep.CHAIN_STEP_OBSERVATION, cause)


@pytest.mark.asyncio
async def test_a_refused_step_planning_judges_the_chain_with_the_steps_it_has():
    fake_llm = given.a_fake_llm_refusing_the_chain_step_planning()
    fake_mcp_client = FakeMCPClient([given.a_tool(name="get_user")])
    graph = given.a_graph(fake_llm, fake_mcp_client)
    state = given.an_initial_state(test_budget=1, chain_budget=1, max_chain_steps=3)

    result = await given.invoke_graph(graph, state)

    report = then.tool_report_at(result, 0)
    then.report_has_chains(report, 1)
    assert len(report.chains[0].steps) == 1
    then.chain_has_eval_result(report.chains[0])
    then.audit_report_has_missed_steps(result, [("get_user", AuditStep.CHAIN_STEP_PLANNING)])
