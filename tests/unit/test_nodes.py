from typing import Any

import pytest
from langgraph.graph import END  # type: ignore[import-untyped]

import tests.unit.fixtures.test_nodes_given as given
import tests.unit.fixtures.test_nodes_then as then
from mcp_auditor.domain import TestCaseBatch, ToolResponse
from mcp_auditor.graph.nodes import (
    filter_tools,
    make_discover_tools,
    make_execute_tool,
    make_finalize_tool_audit,
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


class TestPrepareTools:
    @pytest.mark.asyncio
    async def test_extracts_current_tool(self):
        tools = [given.a_tool(name="t1"), given.a_tool(name="t2"), given.a_tool(name="t3")]
        node = make_prepare_tool()

        result = await node({"discovered_tools": tools, "tool_reports": [object()]})

        then.current_tool_is(result, tools[1])


class TestGenerateTestCases:
    @pytest.mark.asyncio
    async def test_produces_pending_cases(self):
        payloads = [given.a_payload() for _ in range(3)]
        batch = TestCaseBatch(cases=payloads)
        llm = given.a_fake_llm_returning(batch)
        node = make_generate_test_cases(llm)
        tool = given.a_tool()

        result = await node({"current_tool": tool, "test_budget": 3})

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
        node = make_finalize_tool_audit()

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


class TestParseToolsFilter:
    def test_parses_comma_separated(self):
        from mcp_auditor.cli import parse_tools_filter

        assert parse_tools_filter("a,b,c") == frozenset({"a", "b", "c"})

    def test_none_when_not_provided(self):
        from mcp_auditor.cli import parse_tools_filter

        assert parse_tools_filter(None) is None

    def test_none_for_empty_string(self):
        from mcp_auditor.cli import parse_tools_filter

        assert parse_tools_filter("") is None

    def test_strips_whitespace(self):
        from mcp_auditor.cli import parse_tools_filter

        assert parse_tools_filter(" a , b ") == frozenset({"a", "b"})
