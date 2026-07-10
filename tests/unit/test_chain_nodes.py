from typing import Any

import pytest
from langgraph.graph import END  # type: ignore[import-untyped]

import tests.unit.support.test_chain_nodes_given as given
import tests.unit.support.test_chain_nodes_then as then
from mcp_auditor.domain import (
    AuditCategory,
    ChainPlanBatch,
    EvalVerdict,
    Severity,
    StepObservation,
    ToolResponse,
)
from mcp_auditor.graph.chain_nodes import (
    make_execute_step,
    make_judge_chain,
    make_observe_step,
    make_plan_chains,
    make_plan_step,
    prepare_chain,
    route_after_judge,
    route_after_observe,
    route_after_planning,
    route_to_chains_or_report,
)
from tests.fakes import FakeLLM


class TestMakePlanChains:
    @pytest.mark.asyncio
    async def test_produces_pending_chains(self):
        goal_a = given.a_chain_goal(description="chain A")
        goal_b = given.a_chain_goal(description="chain B")
        batch = ChainPlanBatch(chains=[goal_a, goal_b])
        llm = FakeLLM([batch])
        node = make_plan_chains(llm)
        state = given.a_chain_audit_state(chain_budget=2)

        result = await node(state)

        then.pending_chains_count(result, 2)


class TestPrepareChain:
    def test_pops_first_goal_and_sets_state(self):
        goal_a = given.a_chain_goal(description="goal A")
        goal_b = given.a_chain_goal(description="goal B")
        state = given.a_chain_audit_state(pending_chains=[goal_a, goal_b])

        result = prepare_chain(state)

        then.current_chain_goal_is(result, goal_a)
        then.pending_chains_count(result, 1)
        assert result["current_chain_steps"] == []
        assert result["current_step_payload"] == goal_a.first_step


class TestMakeExecuteStep:
    @pytest.mark.asyncio
    async def test_records_successful_response(self):
        tool = given.a_tool()
        payload = given.a_payload()
        client = given.a_fake_mcp_client(
            responses={tool.name: ToolResponse(content="found /data/projects")}
        )
        node = make_execute_step(client)
        state = given.a_chain_audit_state(
            tool=tool,
            current_step_payload=payload,
        )

        result = await node(state)

        assert len(result["current_chain_steps"]) == 1
        step = result["current_chain_steps"][0]
        assert step.response == "found /data/projects"
        assert step.error is None

    @pytest.mark.asyncio
    async def test_records_error_response(self):
        tool = given.a_tool()
        payload = given.a_payload()
        client = given.a_fake_mcp_client(
            responses={tool.name: ToolResponse(content="denied", is_error=True)}
        )
        node = make_execute_step(client)
        state = given.a_chain_audit_state(
            tool=tool,
            current_step_payload=payload,
        )

        result = await node(state)

        step = result["current_chain_steps"][0]
        assert step.error == "denied"
        assert step.response is None


class TestMakeObserveStep:
    @pytest.mark.asyncio
    async def test_updates_observation_and_returns_it(self):
        observation = StepObservation(
            observation="found path", should_continue=True, next_step_hint="try traversal"
        )
        llm = FakeLLM([observation])
        node = make_observe_step(llm)
        existing_step = given.a_chain_step(response="some data")
        goal = given.a_chain_goal()
        state = given.a_chain_audit_state(
            current_chain_goal=goal,
            current_chain_steps=[existing_step],
        )

        result = await node(state)

        latest = result["current_chain_steps"][-1]
        assert latest.observation == "found path"
        assert result["current_observation"].should_continue is True


class TestMakePlanStep:
    @pytest.mark.asyncio
    async def test_returns_next_payload(self):
        next_payload = given.a_payload(
            description="next step", arguments={"path": "../../../etc/shadow"}
        )
        llm = FakeLLM([next_payload])
        node = make_plan_step(llm)
        goal = given.a_chain_goal()
        observation = given.a_step_observation(next_step_hint="try traversal")
        step = given.a_chain_step(observation="found path")
        state = given.a_chain_audit_state(
            current_chain_goal=goal,
            current_chain_steps=[step],
            current_observation=observation,
        )

        result = await node(state)

        assert result["current_step_payload"] == next_payload


class TestMakeJudgeChain:
    @pytest.mark.asyncio
    async def test_stamps_identity_and_deterministic_payload(self):
        judgment = given.a_judgment(verdict=EvalVerdict.FAIL, severity=Severity.HIGH)
        llm = FakeLLM([judgment])
        node = make_judge_chain(llm)
        tool = given.a_tool(name="file_manager")
        goal = given.a_chain_goal(category=AuditCategory.INJECTION)
        last_payload = given.a_payload(arguments={"path": "/etc/shadow"})
        steps = [given.a_chain_step(), given.a_chain_step(payload=last_payload)]
        state = given.a_chain_audit_state(
            tool=tool,
            current_chain_goal=goal,
            current_chain_steps=steps,
        )

        result = await node(state)

        then.completed_chains_count(result, 1)
        chain = result["completed_chains"][0]
        then.chain_has_steps(chain, 2)
        then.chain_eval_result_is(
            chain,
            tool_name="file_manager",
            category=AuditCategory.INJECTION,
            payload={"path": "/etc/shadow"},
            verdict=EvalVerdict.FAIL,
        )


class TestRouteAfterObserve:
    def test_continues_when_should_continue_and_under_max(self):
        observation = given.a_step_observation(should_continue=True)
        state: dict[str, Any] = {
            "current_observation": observation,
            "current_chain_steps": [given.a_chain_step()],
            "max_chain_steps": 5,
        }
        assert route_after_observe(state) == "plan_step"

    def test_stops_when_should_not_continue(self):
        observation = given.a_step_observation(should_continue=False)
        state: dict[str, Any] = {
            "current_observation": observation,
            "current_chain_steps": [given.a_chain_step()],
            "max_chain_steps": 5,
        }
        assert route_after_observe(state) == "judge_chain"

    def test_stops_when_at_max_steps(self):
        observation = given.a_step_observation(should_continue=True)
        steps = [given.a_chain_step() for _ in range(3)]
        state: dict[str, Any] = {
            "current_observation": observation,
            "current_chain_steps": steps,
            "max_chain_steps": 3,
        }
        assert route_after_observe(state) == "judge_chain"


class TestRouteAfterJudge:
    def test_continues_when_pending_chains_remain(self):
        state: dict[str, Any] = {"pending_chains": [given.a_chain_goal()]}
        assert route_after_judge(state) == "prepare_chain"

    def test_ends_when_no_pending_chains(self):
        state: dict[str, Any] = {"pending_chains": []}
        assert route_after_judge(state) == END


class TestRouteAfterPlanning:
    def test_continues_when_pending_chains_exist(self):
        state: dict[str, Any] = {"pending_chains": [given.a_chain_goal()]}
        assert route_after_planning(state) == "prepare_chain"

    def test_ends_when_no_pending_chains(self):
        state: dict[str, Any] = {"pending_chains": []}
        assert route_after_planning(state) == END


class TestRouteToChainsOrReport:
    def test_routes_to_chains_when_budget_positive(self):
        state: dict[str, Any] = {"chain_budget": 2}
        assert route_to_chains_or_report(state) == "chain_audit_tool"

    def test_routes_to_report_when_budget_zero(self):
        state: dict[str, Any] = {"chain_budget": 0}
        assert route_to_chains_or_report(state) == "build_tool_report"
