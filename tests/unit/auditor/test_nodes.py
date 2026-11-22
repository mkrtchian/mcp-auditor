from typing import Any

from langgraph.graph import END

import tests.unit.auditor.support.test_nodes_given as given
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.model_calls import ModelCallKind
from mcp_auditor.domain.models import AttackContext, CoverageGap
from mcp_auditor.domain.server_liveness import Relaunch, RelaunchCause, UnsentCause
from mcp_auditor.graph.nodes import (
    build_tool_report,
    generate_report,
    make_discover_tools,
    make_extract_attack_context,
    make_route_tools,
    prepare_tool,
    route_after_discovery,
    route_test_cases,
)
from tests.fakes import FakeLLM, FakeMCPClient
from tests.fakes.llm import FAKE_USAGE
from tests.unit.auditor.support.audited_servers import a_server_taken_as_down
from tests.unit.auditor.support.graph_builders import a_test_case, a_tool
from tests.unit.auditor.support.model_failures import a_provider_refusal, a_recorded_refusal


class TestDiscoverTools:
    async def test_populates_state(self):
        tools = [a_tool(name="tool_a"), a_tool(name="tool_b")]
        client = FakeMCPClient(tools)
        node = make_discover_tools(AuditedServer(client))

        result = await node({})

        assert [t.name for t in result["discovered_tools"]] == ["tool_a", "tool_b"]

    async def test_filters_tools_by_name(self):
        tools = [a_tool(name="a"), a_tool(name="b"), a_tool(name="c")]
        client = FakeMCPClient(tools)
        node = make_discover_tools(AuditedServer(client), tools_filter=frozenset({"a", "c"}))

        result = await node({})

        assert [t.name for t in result["discovered_tools"]] == ["a", "c"]

    async def test_orders_tools_for_audit(self):
        tools = [a_tool(name="delete_user"), a_tool(name="get_user")]
        client = FakeMCPClient(tools)
        node = make_discover_tools(AuditedServer(client))

        result = await node({})

        assert [t.name for t in result["discovered_tools"]] == ["get_user", "delete_user"]


class TestPrepareTools:
    async def test_extracts_current_tool(self):
        tools = [a_tool(name="t1"), a_tool(name="t2"), a_tool(name="t3")]

        result = await prepare_tool({"discovered_tools": tools, "tool_reports": [object()]})

        assert result["current_tool"] == tools[1]

    async def test_resets_the_coverage_gap_and_the_calls_not_sent(self):
        tools = [a_tool(name="t1")]

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
        refusal = a_provider_refusal()
        node = make_extract_attack_context(FakeLLM([refusal]))
        state = {
            "tool_reports": [given.a_tool_report(tool_name="read_file")],
            "attack_context": previous,
        }

        result = await node(state)

        assert result["attack_context"] == previous
        assert result["missed_model_calls"] == [
            a_recorded_refusal("read_file", ModelCallKind.CONTEXT_EXTRACTION)
        ]
        assert result["provider_usage"] == [refusal.usage]


class TestFinalizeToolAudit:
    async def test_creates_report(self):
        tool = a_tool()
        judged = [given.a_judged_case(response="r1"), given.a_judged_case(response="r2")]

        result = await build_tool_report({"current_tool": tool, "processed_cases": judged})

        assert result["tool_reports"][0].cases == judged

    async def test_copies_the_coverage_gap(self):
        gap = given.a_coverage_gap()
        state: dict[str, Any] = {
            "current_tool": a_tool(),
            "processed_cases": [],
            "coverage_gap": gap,
        }

        result = await build_tool_report(state)

        assert result["tool_reports"][0].coverage_gap == gap

    async def test_reads_no_gap_from_an_older_checkpoint(self):
        result = await build_tool_report({"current_tool": a_tool(), "processed_cases": []})

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
        state = {"discovered_tools": [a_tool()]}
        assert route_after_discovery(state) == "prepare_tool"

    def test_skips_when_empty(self):
        state: dict[str, Any] = {"discovered_tools": []}
        assert route_after_discovery(state) == "generate_report"


class TestRouteTestCases:
    def test_continues_when_cases_pending(self):
        state = {"pending_cases": [a_test_case()]}
        assert route_test_cases(state) == "execute_tool"

    def test_ends_when_no_cases(self):
        state: dict[str, Any] = {"pending_cases": []}
        assert route_test_cases(state) == END


class TestRouteTools:
    def test_continues_when_tools_remain(self):
        route = make_route_tools(AuditedServer(FakeMCPClient([])))
        state = {
            "tool_reports": [object()],
            "discovered_tools": [a_tool(), a_tool(), a_tool()],
        }
        assert route(state) == "prepare_tool"

    def test_ends_when_all_done(self):
        route = make_route_tools(AuditedServer(FakeMCPClient([])))
        state = {
            "tool_reports": [object(), object()],
            "discovered_tools": [a_tool(), a_tool()],
        }
        assert route(state) == "generate_report"

    async def test_reports_the_tools_left_once_the_server_is_taken_as_down(self):
        server, _ = await a_server_taken_as_down(a_tool())
        state = {"tool_reports": [object()], "discovered_tools": [a_tool(), a_tool()]}

        assert make_route_tools(server)(state) == "report_tools_left"


class TestGenerateReport:
    async def test_copies_the_relaunches(self):
        relaunch = Relaunch(tool_name="t", arguments={}, cause=RelaunchCause.STUCK, succeeded=True)
        state: dict[str, Any] = {"server_command": "python server.py", "relaunches": [relaunch]}

        result = await generate_report(state)

        assert result["audit_report"].relaunches == [relaunch]
