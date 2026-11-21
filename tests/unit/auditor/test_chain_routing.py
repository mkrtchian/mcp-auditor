from typing import Any

from langgraph.graph import END  # type: ignore[import-untyped]

from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.server_liveness import UnsentCause
from mcp_auditor.graph.chain_nodes import (
    make_route_to_chains_or_report,
    route_after_execute_step,
    route_after_judge,
    route_after_observe,
    route_after_plan_step,
    route_after_planning,
)
from tests.unit.auditor.support.audited_servers import (
    a_server_taken_as_down,
    a_server_that_stopped,
)
from tests.unit.auditor.support.chain_states import (
    a_chain_audit_state,
    a_chain_goal,
    a_chain_step,
    a_fake_mcp_client,
    a_step_observation,
    a_tool,
)


class TestRouteAfterObserve:
    def test_continues_when_should_continue_and_under_max(self):
        observation = a_step_observation(should_continue=True)
        state: dict[str, Any] = {
            "current_observation": observation,
            "current_chain_steps": [a_chain_step()],
            "max_chain_steps": 5,
            "chain_model_call_missed": False,
        }
        assert route_after_observe(state) == "plan_step"

    def test_stops_when_should_not_continue(self):
        observation = a_step_observation(should_continue=False)
        state: dict[str, Any] = {
            "current_observation": observation,
            "current_chain_steps": [a_chain_step()],
            "max_chain_steps": 5,
            "chain_model_call_missed": False,
        }
        assert route_after_observe(state) == "judge_chain"

    def test_stops_when_at_max_steps(self):
        observation = a_step_observation(should_continue=True)
        steps = [a_chain_step() for _ in range(3)]
        state: dict[str, Any] = {
            "current_observation": observation,
            "current_chain_steps": steps,
            "max_chain_steps": 3,
            "chain_model_call_missed": False,
        }
        assert route_after_observe(state) == "judge_chain"

    def test_judges_the_chain_when_a_model_call_was_missed(self):
        state: dict[str, Any] = {"chain_model_call_missed": True}
        assert route_after_observe(state) == "judge_chain"


class TestRouteAfterPlanStep:
    def test_executes_the_planned_step(self):
        state: dict[str, Any] = {"chain_model_call_missed": False}
        assert route_after_plan_step(state) == "execute_step"

    def test_judges_the_chain_when_a_model_call_was_missed(self):
        state: dict[str, Any] = {"chain_model_call_missed": True}
        assert route_after_plan_step(state) == "judge_chain"


class TestRouteAfterExecuteStep:
    def test_observes_a_step_that_ran(self):
        state: dict[str, Any] = {
            "blocked_step_reason": None,
            "current_chain_steps": [a_chain_step()],
        }
        assert route_after_execute_step(state) == "observe_step"

    def test_judges_the_prefix_when_a_later_step_is_blocked(self):
        state: dict[str, Any] = {
            "blocked_step_reason": "destructive filesystem command: rm -rf",
            "current_chain_steps": [a_chain_step()],
        }
        assert route_after_execute_step(state) == "judge_chain"

    def test_abandons_the_chain_when_the_first_step_is_blocked(self):
        state: dict[str, Any] = {
            "blocked_step_reason": "destructive filesystem command: rm -rf",
            "current_chain_steps": [],
        }
        assert route_after_execute_step(state) == "abandon_chain"

    def test_judges_the_steps_made_before_a_step_not_sent(self):
        state: dict[str, Any] = {
            "unsent_step_cause": UnsentCause.SERVER_DOWN,
            "current_chain_steps": [a_chain_step()],
        }
        assert route_after_execute_step(state) == "judge_chain"

    def test_counts_a_chain_whose_first_step_is_not_sent(self):
        state: dict[str, Any] = {
            "unsent_step_cause": UnsentCause.SERVER_DOWN,
            "current_chain_steps": [],
        }
        assert route_after_execute_step(state) == "count_unsent_chain"

    def test_judges_a_chain_cut_by_a_relaunch(self):
        state: dict[str, Any] = {
            "chain_cut_by_relaunch": True,
            "blocked_step_reason": None,
            "current_chain_steps": [a_chain_step()],
        }
        assert route_after_execute_step(state) == "judge_chain"


class TestRouteAfterJudge:
    def test_continues_when_pending_chains_remain(self):
        state: dict[str, Any] = {"pending_chains": [a_chain_goal()]}
        assert route_after_judge(state) == "prepare_chain"

    def test_ends_when_no_pending_chains(self):
        state: dict[str, Any] = {"pending_chains": []}
        assert route_after_judge(state) == END


class TestRouteAfterPlanning:
    def test_continues_when_pending_chains_exist(self):
        state: dict[str, Any] = {"pending_chains": [a_chain_goal()]}
        assert route_after_planning(state) == "prepare_chain"

    def test_ends_when_no_pending_chains(self):
        state: dict[str, Any] = {"pending_chains": []}
        assert route_after_planning(state) == END


class TestRouteToChainsOrReport:
    def test_routes_to_chains_when_budget_positive(self):
        route = make_route_to_chains_or_report(AuditedServer(a_fake_mcp_client()))

        assert route(a_chain_audit_state(chain_budget=2)) == "chain_audit_tool"

    def test_routes_to_report_when_budget_zero(self):
        route = make_route_to_chains_or_report(AuditedServer(a_fake_mcp_client()))

        assert route(a_chain_audit_state(chain_budget=0)) == "build_tool_report"

    async def test_plans_no_chains_for_a_stopped_tool(self):
        route = make_route_to_chains_or_report(await a_server_that_stopped(a_tool()))

        assert route(a_chain_audit_state(chain_budget=2)) == "count_chains_not_planned"

    async def test_plans_no_chains_on_a_server_taken_as_down(self):
        server, _ = await a_server_taken_as_down(a_tool())

        route = make_route_to_chains_or_report(server)

        assert route(a_chain_audit_state(chain_budget=2)) == "count_chains_not_planned"
