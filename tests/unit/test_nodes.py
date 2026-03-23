from typing import Any

import pytest
from langgraph.graph import END  # type: ignore[import-untyped]

import tests.unit.fixtures.test_nodes_given as given
import tests.unit.fixtures.test_nodes_then as then
from mcp_auditor.domain import AttackContext, TestCaseBatch, ToolResponse
from mcp_auditor.domain.models import filter_tools
from mcp_auditor.graph.nodes import (
    make_build_tool_report,
    make_discover_tools,
    make_execute_tool,
    make_extract_attack_context,
    make_generate_test_cases,
    make_judge_response,
    make_prepare_tool,
    route_after_discovery,
    route_test_cases,
    route_tools,
)


class TestFilterTools:
    def test_filters_tools_by_name(self):
        tools = [given.a_tool(name="a"), given.a_tool(name="b"), given.a_tool(name="c")]

        result = filter_tools(tools, frozenset({"a", "c"}))

        then.discovered_tools_are(result, ["a", "c"])

    def test_raises_on_unknown_tool_name(self):
        tools = [given.a_tool(name="a"), given.a_tool(name="b")]

        with pytest.raises(ValueError, match="unknown"):
            filter_tools(tools, frozenset({"a", "unknown"}))

    def test_no_filter_returns_all(self):
        tools = [given.a_tool(name="a"), given.a_tool(name="b")]

        result = filter_tools(tools, None)

        then.discovered_tools_are(result, ["a", "b"])

    def test_preserves_server_order(self):
        tools = [given.a_tool(name="c"), given.a_tool(name="a"), given.a_tool(name="b")]

        result = filter_tools(tools, frozenset({"b", "c"}))

        then.discovered_tools_are(result, ["c", "b"])


class TestDiscoverTools:
    @pytest.mark.asyncio
    async def test_populates_state(self):
        tools = [given.a_tool(name="tool_a"), given.a_tool(name="tool_b")]
        client = given.a_fake_mcp_client(tools)
        node = make_discover_tools(client)

        result = await node({})

        then.discovered_tools_count(result, 2)

    @pytest.mark.asyncio
    async def test_filters_tools_by_name(self):
        tools = [given.a_tool(name="a"), given.a_tool(name="b"), given.a_tool(name="c")]
        client = given.a_fake_mcp_client(tools)
        node = make_discover_tools(client, tools_filter=frozenset({"a", "c"}))

        result = await node({})

        then.discovered_tools_count(result, 2)
        then.discovered_tools_are(result["discovered_tools"], ["a", "c"])

    @pytest.mark.asyncio
    async def test_orders_tools_for_audit(self):
        tools = [given.a_tool(name="delete_user"), given.a_tool(name="get_user")]
        client = given.a_fake_mcp_client(tools)
        node = make_discover_tools(client)

        result = await node({})

        then.discovered_tools_are(result["discovered_tools"], ["get_user", "delete_user"])


class TestPrepareTools:
    @pytest.mark.asyncio
    async def test_extracts_current_tool(self):
        tools = [given.a_tool(name="t1"), given.a_tool(name="t2"), given.a_tool(name="t3")]
        node = make_prepare_tool()

        result = await node({"discovered_tools": tools, "tool_reports": [object()]})

        then.current_tool_is(result, tools[1])


class TestExtractAttackContext:
    @pytest.mark.asyncio
    async def test_extracts_context_from_tool_report(self):
        report = given.a_tool_report()
        llm = given.a_fake_llm_returning(AttackContext(db_engine="sqlite"))
        node = make_extract_attack_context(llm)

        result = await node({"tool_reports": [report], "attack_context": AttackContext()})

        then.attack_context_has_db_engine(result, "sqlite")

    @pytest.mark.asyncio
    async def test_accumulates_token_usage(self):
        report = given.a_tool_report()
        llm = given.a_fake_llm_returning(AttackContext(db_engine="sqlite"))
        node = make_extract_attack_context(llm)

        result = await node({"tool_reports": [report], "attack_context": AttackContext()})

        assert len(result["token_usage"]) == 1


class TestGenerateTestCases:
    @pytest.mark.asyncio
    async def test_produces_pending_cases(self):
        payloads = [given.a_payload() for _ in range(3)]
        batch = TestCaseBatch(cases=payloads)
        llm = given.a_fake_llm_returning(batch)
        node = make_generate_test_cases(llm)
        tool = given.a_tool()

        result = await node(
            {"current_tool": tool, "test_budget": 3, "attack_context": AttackContext()}
        )

        then.pending_cases_count(result, 3)
        then.judged_cases_count(result, 0)


class TestExecuteTool:
    @pytest.mark.asyncio
    async def test_success(self):
        tool = given.a_tool(name="my_tool")
        case = given.a_test_case(tool_name="my_tool")
        client = given.a_fake_mcp_client(
            [tool], responses={"my_tool": ToolResponse(content="result data")}
        )
        node = make_execute_tool(client)

        result = await node({"pending_cases": [case], "current_tool": tool})

        then.current_case_has_response(result, "result data")
        then.pending_cases_count(result, 0)

    @pytest.mark.asyncio
    async def test_error(self):
        tool = given.a_tool(name="my_tool")
        case = given.a_test_case(tool_name="my_tool")
        client = given.a_fake_mcp_client(
            [tool],
            responses={"my_tool": ToolResponse(content="not found", is_error=True)},
        )
        node = make_execute_tool(client)

        result = await node({"pending_cases": [case], "current_tool": tool})

        then.current_case_has_error(result, "not found")


class TestJudgeResponse:
    @pytest.mark.asyncio
    async def test_produces_eval_result(self):
        eval_result = given.an_eval_result()
        llm = given.a_fake_llm_returning(eval_result)
        node = make_judge_response(llm)
        case = given.a_test_case(response="some output")
        tool = given.a_tool()

        result = await node({"current_case": case, "judged_cases": [], "current_tool": tool})

        then.judged_cases_count(result, 1)
        judged_case = result["judged_cases"][0]
        assert judged_case.eval_result is not None
        assert judged_case.eval_result.verdict == eval_result.verdict


class TestFinalizeToolAudit:
    @pytest.mark.asyncio
    async def test_creates_report(self):
        tool = given.a_tool()
        case1 = given.a_test_case(response="r1")
        case1 = case1.model_copy(update={"eval_result": given.an_eval_result()})
        case2 = given.a_test_case(response="r2")
        case2 = case2.model_copy(update={"eval_result": given.an_eval_result()})
        node = make_build_tool_report()

        result = await node({"current_tool": tool, "judged_cases": [case1, case2]})

        then.tool_report_has_cases(result, 2)


class TestRouteAfterDiscovery:
    def test_continues_when_tools_found(self):
        state = {"discovered_tools": [given.a_tool()]}
        assert route_after_discovery(state) == "prepare_tool"

    def test_skips_when_empty(self):
        state: dict[str, Any] = {"discovered_tools": []}
        assert route_after_discovery(state) == "generate_report"


class TestRouteTestCases:
    def test_continues_when_cases_pending(self):
        state = {"pending_cases": [given.a_test_case()]}
        assert route_test_cases(state) == "execute_tool"

    def test_ends_when_no_cases(self):
        state: dict[str, Any] = {"pending_cases": []}
        assert route_test_cases(state) == END


class TestRouteTools:
    def test_continues_when_tools_remain(self):
        state = {
            "tool_reports": [object()],
            "discovered_tools": [given.a_tool(), given.a_tool(), given.a_tool()],
        }
        assert route_tools(state) == "prepare_tool"

    def test_ends_when_all_done(self):
        state = {
            "tool_reports": [object(), object()],
            "discovered_tools": [given.a_tool(), given.a_tool()],
        }
        assert route_tools(state) == "generate_report"
