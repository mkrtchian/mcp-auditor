from typing import Any

import pytest
from langgraph.graph import END  # type: ignore[import-untyped]

import tests.unit.auditor.support.test_nodes_given as given
import tests.unit.auditor.support.test_nodes_then as then
from mcp_auditor.domain import (
    AttackContext,
    AuditCategory,
    CoverageGap,
    EvalVerdict,
    Severity,
    ToolResponse,
)
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import ModelCallKind, filter_tools
from mcp_auditor.domain.server_liveness import Relaunch, RelaunchCause, UnsentCause
from mcp_auditor.graph.nodes import (
    build_tool_report,
    generate_report,
    make_discover_tools,
    make_execute_tool,
    make_extract_attack_context,
    make_generate_test_cases,
    make_judge_response,
    make_route_tools,
    prepare_tool,
    route_after_discovery,
    route_after_execute,
    route_test_cases,
)
from tests.fakes import FakeLLM, FakeMCPClient
from tests.fakes.llm import FAKE_USAGE
from tests.fakes.mcp_client import a_lost_connection_response
from tests.unit.auditor.support.audited_servers import a_server_taken_as_down


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
    async def test_populates_state(self):
        tools = [given.a_tool(name="tool_a"), given.a_tool(name="tool_b")]
        client = FakeMCPClient(tools)
        node = make_discover_tools(AuditedServer(client))

        result = await node({})

        then.discovered_tools_are(result["discovered_tools"], ["tool_a", "tool_b"])

    async def test_filters_tools_by_name(self):
        tools = [given.a_tool(name="a"), given.a_tool(name="b"), given.a_tool(name="c")]
        client = FakeMCPClient(tools)
        node = make_discover_tools(AuditedServer(client), tools_filter=frozenset({"a", "c"}))

        result = await node({})

        then.discovered_tools_are(result["discovered_tools"], ["a", "c"])

    async def test_orders_tools_for_audit(self):
        tools = [given.a_tool(name="delete_user"), given.a_tool(name="get_user")]
        client = FakeMCPClient(tools)
        node = make_discover_tools(AuditedServer(client))

        result = await node({})

        then.discovered_tools_are(result["discovered_tools"], ["get_user", "delete_user"])


class TestPrepareTools:
    async def test_extracts_current_tool(self):
        tools = [given.a_tool(name="t1"), given.a_tool(name="t2"), given.a_tool(name="t3")]

        result = await prepare_tool({"discovered_tools": tools, "tool_reports": [object()]})

        assert result["current_tool"] == tools[1]

    async def test_resets_the_coverage_gap_and_the_calls_not_sent(self):
        tools = [given.a_tool(name="t1")]

        result = await prepare_tool({"discovered_tools": tools, "tool_reports": []})

        assert result["coverage_gap"] is None
        assert (result["unsent_cases"], result["unsent_chains"]) == (0, 0)
        assert result["unsent_cause"] is None


class TestExtractAttackContext:
    async def test_extracts_context_from_tool_report(self):
        report = given.a_tool_report()
        llm = FakeLLM([AttackContext(db_engine="sqlite")])
        node = make_extract_attack_context(llm)

        result = await node({"tool_reports": [report], "attack_context": AttackContext()})

        assert result["attack_context"] == AttackContext(db_engine="sqlite")

    async def test_merges_the_answer_into_the_carried_context(self):
        carried = AttackContext(exposed_internals=["/srv/app/config.yaml"])
        answer = AttackContext(exposed_internals=["users table"], observations="echoes the path")
        node = make_extract_attack_context(FakeLLM([answer]))
        state = {
            "tool_reports": [given.a_tool_report(tool_name="read_file")],
            "attack_context": carried,
        }

        result = await node(state)

        context = result["attack_context"]
        assert context.exposed_internals == ["/srv/app/config.yaml", "users table"]
        assert context.observations == "read_file: echoes the path"

    async def test_records_the_usage_of_the_extraction(self):
        report = given.a_tool_report()
        llm = FakeLLM([AttackContext(db_engine="sqlite")])
        node = make_extract_attack_context(llm)

        result = await node({"tool_reports": [report], "attack_context": AttackContext()})

        assert result["provider_usage"] == [FAKE_USAGE]

    async def test_a_refused_extraction_keeps_the_previous_context(self):
        previous = AttackContext(db_engine="postgres")
        refusal = given.a_provider_refusal()
        node = make_extract_attack_context(FakeLLM([refusal]))
        state = {
            "tool_reports": [given.a_tool_report(tool_name="read_file")],
            "attack_context": previous,
        }

        result = await node(state)

        assert result["attack_context"] == previous
        then.refused_call_recorded(
            result, tool_name="read_file", kind=ModelCallKind.CONTEXT_EXTRACTION
        )
        assert result["provider_usage"] == [refusal.usage]


class TestExecuteTool:
    async def test_records_the_response_of_the_current_tool(self):
        tool = given.a_tool(name="read_file")
        case = given.a_test_case()
        client = FakeMCPClient(
            [tool], responses={"read_file": ToolResponse(content="read_file was called")}
        )
        node = make_execute_tool(AuditedServer(client))

        result = await node({"pending_cases": [case], "current_tool": tool})

        assert result["current_case"].response == "read_file was called"
        assert result["current_case"].blocked_reason is None
        assert result["pending_cases"] == []

    async def test_error(self):
        tool = given.a_tool(name="my_tool")
        case = given.a_test_case()
        client = FakeMCPClient(
            [tool],
            responses={"my_tool": ToolResponse(content="not found", is_error=True)},
        )
        node = make_execute_tool(AuditedServer(client))

        result = await node({"pending_cases": [case], "current_tool": tool})

        then.current_case_has_error(result, "not found")

    async def test_records_a_destructive_case_as_blocked_without_calling_the_server(self):
        tool = given.a_tool(name="run_command")
        case = given.a_test_case(payload=given.a_payload(arguments={"command": "rm -rf /"}))
        client = FakeMCPClient([tool])
        node = make_execute_tool(AuditedServer(client))

        result = await node({"pending_cases": [case], "current_tool": tool})

        [blocked] = result["processed_cases"]
        assert blocked.blocked_reason is not None
        assert client.calls == []

    async def test_blocked_case_holds_no_verdict_and_no_server_output(self):
        tool = given.a_tool(name="run_command")
        case = given.a_test_case(payload=given.a_payload(arguments={"command": "rm -rf /"}))
        node = make_execute_tool(AuditedServer(FakeMCPClient([tool])))

        result = await node({"pending_cases": [case], "current_tool": tool})

        blocked = result["processed_cases"][0]
        assert blocked.judge_result is None
        assert blocked.response is None
        assert blocked.error is None
        assert result["current_case"] is None

    async def test_a_case_not_sent_is_counted_apart_and_not_judged(self):
        tool = given.a_tool(name="read_file")
        server, client = await a_server_taken_as_down(tool)
        node = make_execute_tool(server)
        state: dict[str, Any] = {"pending_cases": [given.a_test_case()], "current_tool": tool}

        result = await node(state)

        assert "processed_cases" not in result
        assert result["unsent_cases"] == 1
        assert result["unsent_cause"] is UnsentCause.SERVER_DOWN
        assert (result["current_case"], result["pending_cases"]) == (None, [])
        assert len(client.calls) == 1

    async def test_a_case_followed_by_a_relaunch_keeps_its_error_and_the_relaunch(self):
        tool = given.a_tool(name="read_file")
        client = FakeMCPClient([tool], responses={"read_file": a_lost_connection_response()})
        node = make_execute_tool(AuditedServer(client))
        case = given.a_test_case()
        state: dict[str, Any] = {"pending_cases": [case], "current_tool": tool}

        result = await node(state)

        assert result["relaunches"] == [
            Relaunch(
                tool_name="read_file",
                arguments=case.payload.arguments,
                cause=RelaunchCause.LOST_CONNECTION,
                succeeded=True,
            )
        ]
        then.current_case_has_error(result, "Connection closed")

    async def test_a_case_that_is_sent_leaves_the_cause_of_calls_not_sent_as_it_was(self):
        tool = given.a_tool(name="read_file")
        node = make_execute_tool(AuditedServer(FakeMCPClient([tool])))
        state: dict[str, Any] = {
            "pending_cases": [given.a_test_case()],
            "current_tool": tool,
            "unsent_cause": UnsentCause.TOOL_TIMING_OUT,
        }

        result = await node(state)

        assert "unsent_cause" not in result


class TestJudgeResponse:
    async def test_stamps_identity_and_uses_judgment(self):
        judgment = given.a_judgment(verdict=EvalVerdict.FAIL, severity=Severity.HIGH)
        llm = FakeLLM([judgment])
        node = make_judge_response(llm)
        case = given.a_test_case(category=AuditCategory.INJECTION, response="some output")
        tool = given.a_tool(name="read_file")

        result = await node({"current_case": case, "processed_cases": [], "current_tool": tool})

        assert len(result["processed_cases"]) == 1
        then.judged_case_identity_from(result, tool_name="read_file", case=case)
        then.judged_case_uses_judgment(result, judgment=judgment)

    async def test_a_refused_judgment_leaves_the_case_unjudged(self):
        refusal = given.a_provider_refusal()
        node = make_judge_response(FakeLLM([refusal]))
        case = given.a_test_case(response="some output")
        tool = given.a_tool(name="read_file")

        result = await node({"current_case": case, "processed_cases": [], "current_tool": tool})

        assert result["processed_cases"] == [case]
        assert result["processed_cases"][0].judge_result is None
        assert result["current_case"] is None
        then.refused_call_recorded(result, tool_name="read_file", kind=ModelCallKind.JUDGMENT)
        assert result["provider_usage"] == [refusal.usage]
        assert result["judge_usage"] == [refusal.usage]
        assert "chain_usage" not in result

    async def test_a_refused_generation_does_not_bill_the_judge(self):
        refusal = given.a_provider_refusal()
        node = make_generate_test_cases(FakeLLM([refusal]))
        state = {
            "current_tool": given.a_tool(name="read_file"),
            "test_budget": 2,
            "attack_context": AttackContext(),
        }

        result = await node(state)

        assert result["provider_usage"] == [refusal.usage]
        assert "judge_usage" not in result


class TestFinalizeToolAudit:
    async def test_creates_report(self):
        tool = given.a_tool()
        judged = [given.a_judged_case(response="r1"), given.a_judged_case(response="r2")]

        result = await build_tool_report({"current_tool": tool, "processed_cases": judged})

        assert result["tool_reports"][0].cases == judged

    async def test_copies_the_coverage_gap(self):
        gap = given.a_coverage_gap()
        state: dict[str, Any] = {
            "current_tool": given.a_tool(),
            "processed_cases": [],
            "coverage_gap": gap,
        }

        result = await build_tool_report(state)

        assert result["tool_reports"][0].coverage_gap == gap

    async def test_reads_no_gap_from_an_older_checkpoint(self):
        result = await build_tool_report({"current_tool": given.a_tool(), "processed_cases": []})

        assert result["tool_reports"][0].coverage_gap is None

    async def test_merges_a_short_generation_and_calls_not_sent_into_one_gap(self):
        state = given.a_tool_state(
            coverage_gap=given.a_coverage_gap(), unsent_cases=1, unsent_chains=2
        )

        result = await build_tool_report(state)

        assert result["tool_reports"][0].coverage_gap == given.a_coverage_gap().model_copy(
            update={
                "unsent_cases": 1,
                "unsent_chains": 2,
                "unsent_cause": UnsentCause.TOOL_TIMING_OUT,
            }
        )

    async def test_a_gap_of_calls_not_sent_keeps_what_generation_gave(self):
        state = given.a_tool_state(test_budget=4, sent_cases=3, unsent_cases=1, unsent_chains=0)

        result = await build_tool_report(state)

        assert result["tool_reports"][0].coverage_gap == CoverageGap(
            requested_cases=4,
            received_cases=4,
            missing_categories=[],
            unsent_cases=1,
            unsent_cause=UnsentCause.TOOL_TIMING_OUT,
        )

    async def test_a_cause_with_no_call_withheld_leaves_no_gap(self):
        state = given.a_tool_state(unsent_cases=0, unsent_chains=0)

        result = await build_tool_report(state)

        assert result["tool_reports"][0].coverage_gap is None


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


class TestRouteAfterExecute:
    def test_judges_an_executed_case(self):
        state: dict[str, Any] = {
            "current_case": given.a_test_case(response="output"),
            "pending_cases": [],
        }
        assert route_after_execute(state) == "judge_response"

    def test_moves_to_the_next_case_after_a_block(self):
        state: dict[str, Any] = {"current_case": None, "pending_cases": [given.a_test_case()]}
        assert route_after_execute(state) == "execute_tool"

    def test_ends_when_a_block_was_the_last_case(self):
        state: dict[str, Any] = {"current_case": None, "pending_cases": []}
        assert route_after_execute(state) == END


class TestRouteTools:
    def test_continues_when_tools_remain(self):
        route = make_route_tools(AuditedServer(FakeMCPClient([])))
        state = {
            "tool_reports": [object()],
            "discovered_tools": [given.a_tool(), given.a_tool(), given.a_tool()],
        }
        assert route(state) == "prepare_tool"

    def test_ends_when_all_done(self):
        route = make_route_tools(AuditedServer(FakeMCPClient([])))
        state = {
            "tool_reports": [object(), object()],
            "discovered_tools": [given.a_tool(), given.a_tool()],
        }
        assert route(state) == "generate_report"

    async def test_reports_the_tools_left_once_the_server_is_taken_as_down(self):
        server, _ = await a_server_taken_as_down(given.a_tool())
        state = {"tool_reports": [object()], "discovered_tools": [given.a_tool(), given.a_tool()]}

        assert make_route_tools(server)(state) == "report_tools_left"


class TestGenerateReport:
    async def test_copies_the_relaunches(self):
        relaunch = Relaunch(tool_name="t", arguments={}, cause=RelaunchCause.STUCK, succeeded=True)
        state: dict[str, Any] = {"server_command": "python server.py", "relaunches": [relaunch]}

        result = await generate_report(state)

        assert result["audit_report"].relaunches == [relaunch]
