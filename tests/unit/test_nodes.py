from typing import Any

import pytest
from langgraph.graph import END  # type: ignore[import-untyped]

import tests.unit.test_nodes_given as given
import tests.unit.test_nodes_then as then
from mcp_auditor.domain import TestCaseBatch, ToolResponse
from mcp_auditor.graph.nodes import (
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


class TestDiscoverTools:
    @pytest.mark.asyncio
    async def test_populates_state(self):
        tools = [given.a_tool(name="tool_a"), given.a_tool(name="tool_b")]
        client = given.a_fake_mcp_client(tools)
        node = make_discover_tools(client)

        result = await node({})

        then.discovered_tools_count(result, 2)


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
        then.tool_results_count(result, 0)


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

        result = await node({"current_case": case, "tool_results": [], "current_tool": tool})

        then.tool_results_count(result, 1)


class TestFinalizeToolAudit:
    @pytest.mark.asyncio
    async def test_creates_report(self):
        tool = given.a_tool()
        results = [given.an_eval_result(), given.an_eval_result()]
        node = make_finalize_tool_audit()

        result = await node({"current_tool": tool, "tool_results": results})

        then.tool_report_has_results(result, 2)


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
