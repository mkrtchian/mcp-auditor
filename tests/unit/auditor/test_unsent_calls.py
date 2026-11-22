from typing import Any

import tests.unit.auditor.support.test_unsent_calls_given as given
from mcp_auditor.domain.models import CoverageGap
from mcp_auditor.domain.server_liveness import UnsentCause
from mcp_auditor.graph.unsent_calls import (
    count_unsent_chain,
    make_count_chains_not_planned,
    report_tools_left,
)
from tests.unit.auditor.support.audited_servers import (
    a_server_taken_as_down,
    a_server_that_stopped,
)


class TestReportToolsLeft:
    def test_gives_each_tool_not_audited_a_server_down_gap(self):
        tools = [given.a_tool(name="audited"), given.a_tool(name="left")]
        state: dict[str, Any] = {
            "discovered_tools": tools,
            "tool_reports": [given.a_tool_report(tool_name="audited")],
            "test_budget": 4,
            "chain_budget": 2,
        }

        result = report_tools_left(state)

        [left] = result["tool_reports"]
        assert (left.tool.name, left.cases, left.chains) == ("left", [], [])
        assert left.coverage_gap == CoverageGap(
            requested_cases=4,
            received_cases=0,
            missing_categories=[],
            unsent_chains=2,
            unsent_cause=UnsentCause.SERVER_DOWN,
        )


class TestCountUnsentChain:
    def test_counts_a_chain_whose_first_step_is_not_sent_and_records_none(self):
        state = given.a_chain_audit_state(current_chain_goal=given.a_chain_goal())

        result = count_unsent_chain(state)

        assert result["unsent_chains"] == 1
        assert "completed_chains" not in result


class TestCountChainsNotPlanned:
    async def test_counts_the_chain_budget_with_the_cause(self):
        count = make_count_chains_not_planned(await a_server_that_stopped(given.a_tool()))

        result = count(given.a_chain_audit_state(chain_budget=3))

        assert result["unsent_chains"] == 3
        assert result["unsent_cause"] == UnsentCause.TOOL_TIMING_OUT

    async def test_drops_the_chains_of_the_tool_audited_before(self):
        server, _ = await a_server_taken_as_down(given.a_tool())
        state = given.a_chain_audit_state(chain_budget=2, completed_chains=[given.a_judged_chain()])

        result = make_count_chains_not_planned(server)(state)

        assert result["completed_chains"] == []
        assert result["unsent_chains"] == 2
        assert result["unsent_cause"] == UnsentCause.SERVER_DOWN
