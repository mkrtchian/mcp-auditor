import tests.unit.auditor.support.test_chain_nodes_given as given
import tests.unit.auditor.support.test_chain_nodes_then as then
from mcp_auditor.domain.model_calls import ModelCallKind
from mcp_auditor.domain.models import AuditCategory, ChainPlanBatch, EvalVerdict, Severity
from mcp_auditor.domain.server_liveness import UnsentCause
from mcp_auditor.graph.chain_nodes import (
    abandon_chain,
    make_judge_chain,
    make_plan_chains,
    prepare_chain,
)
from tests.fakes import FakeLLM
from tests.unit.auditor.support.chain_states import (
    DEFAULT_TOOL_NAME,
    a_chain_audit_state,
    a_chain_goal,
    a_chain_step,
    a_payload,
    a_provider_refusal,
    a_tool,
)
from tests.unit.auditor.support.missed_chain_calls import (
    refused_call_recorded,
)


class TestMakePlanChains:
    async def test_produces_pending_chains(self):
        goal_a = a_chain_goal(description="chain A")
        goal_b = a_chain_goal(description="chain B")
        batch = ChainPlanBatch(chains=[goal_a, goal_b])
        llm = FakeLLM([batch])
        node = make_plan_chains(llm)
        state = a_chain_audit_state(chain_budget=2)

        result = await node(state)

        assert result["pending_chains"] == [goal_a, goal_b]

    async def test_a_refused_planning_plans_no_chain(self):
        refusal = a_provider_refusal()
        node = make_plan_chains(FakeLLM([refusal]))
        state = a_chain_audit_state(chain_budget=2)

        result = await node(state)

        assert result["pending_chains"] == []
        refused_call_recorded(result, ModelCallKind.CHAIN_PLANNING)
        assert result["chain_usage"] == [refusal.usage]


class TestPrepareChain:
    def test_pops_first_goal_and_sets_state(self):
        goal_a = a_chain_goal(description="goal A")
        goal_b = a_chain_goal(description="goal B")
        state = a_chain_audit_state(pending_chains=[goal_a, goal_b])

        result = prepare_chain(state)

        assert result["current_chain_goal"] == goal_a
        assert result["pending_chains"] == [goal_b]
        assert result["current_chain_steps"] == []
        assert result["current_step_payload"] == goal_a.first_step

    def test_clears_a_block_from_the_previous_chain(self):
        state = a_chain_audit_state(
            pending_chains=[a_chain_goal()],
            blocked_step_reason="destructive filesystem command: rm -rf",
        )

        result = prepare_chain(state)

        assert result["blocked_step_reason"] is None

    def test_clears_a_refusal_from_the_previous_chain(self):
        state = a_chain_audit_state(pending_chains=[a_chain_goal()], chain_model_call_missed=True)

        result = prepare_chain(state)

        assert result["chain_model_call_missed"] is False

    def test_clears_a_relaunch_and_a_step_not_sent_from_the_previous_chain(self):
        state = a_chain_audit_state(pending_chains=[a_chain_goal()], chain_cut_by_relaunch=True)

        result = prepare_chain(state)

        assert result["chain_cut_by_relaunch"] is False
        assert result["unsent_step_cause"] is None


class TestMakeJudgeChain:
    async def test_stamps_identity_and_deterministic_payload(self):
        judgment = given.a_judgment(verdict=EvalVerdict.FAIL, severity=Severity.HIGH)
        llm = FakeLLM([judgment])
        node = make_judge_chain(llm)
        tool = a_tool()
        goal = a_chain_goal(category=AuditCategory.INJECTION)
        last_payload = a_payload(arguments={"path": "/etc/shadow"})
        steps = [a_chain_step(), a_chain_step(payload=last_payload)]
        state = a_chain_audit_state(
            tool=tool,
            current_chain_goal=goal,
            current_chain_steps=steps,
        )

        result = await node(state)

        [chain] = result["completed_chains"]
        assert chain.steps == steps
        then.chain_judge_result_is(
            chain,
            tool_name=DEFAULT_TOOL_NAME,
            category=AuditCategory.INJECTION,
            payload={"path": "/etc/shadow"},
            verdict=EvalVerdict.FAIL,
        )

    async def test_a_refused_judgment_completes_the_chain_unjudged(self):
        refusal = a_provider_refusal()
        node = make_judge_chain(FakeLLM([refusal]))
        step = a_chain_step()
        state = a_chain_audit_state(
            current_chain_goal=a_chain_goal(),
            current_chain_steps=[step],
            chain_model_call_missed=True,
        )

        result = await node(state)

        [chain] = result["completed_chains"]
        assert chain.steps == [step]
        assert chain.judge_result is None
        refused_call_recorded(result, ModelCallKind.CHAIN_JUDGMENT)
        assert result["chain_model_call_missed"] is False
        assert result["judge_usage"] == [refusal.usage]
        assert result["chain_usage"] == [refusal.usage]

    async def test_judges_the_steps_made_before_a_blocked_step(self):
        executed = a_chain_step()
        state = a_chain_audit_state(
            current_chain_goal=a_chain_goal(),
            current_chain_steps=[executed],
            blocked_step_reason="destructive SQL command: DROP TABLE",
        )

        result = await make_judge_chain(FakeLLM([given.a_judgment()]))(state)

        [chain] = result["completed_chains"]
        assert (chain.steps, chain.blocked_reason) == (
            [executed],
            "destructive SQL command: DROP TABLE",
        )
        assert chain.judge_result is not None
        assert result["blocked_step_reason"] is None

    async def test_judges_the_steps_made_before_a_step_not_sent(self):
        executed = a_chain_step()
        state = a_chain_audit_state(
            current_chain_goal=a_chain_goal(),
            current_chain_steps=[executed],
            unsent_step_cause=UnsentCause.SERVER_DOWN,
        )

        result = await make_judge_chain(FakeLLM([given.a_judgment()]))(state)

        [chain] = result["completed_chains"]
        assert (chain.steps, chain.blocked_reason) == ([executed], None)
        assert chain.judge_result is not None

    async def test_records_a_chain_cut_by_a_relaunch(self):
        state = a_chain_audit_state(
            current_chain_goal=a_chain_goal(),
            current_chain_steps=[a_chain_step()],
            chain_cut_by_relaunch=True,
        )

        result = await make_judge_chain(FakeLLM([given.a_judgment()]))(state)

        [chain] = result["completed_chains"]
        assert chain.cut_by_relaunch


class TestAbandonChain:
    def test_records_a_chain_blocked_at_its_first_step_with_no_step_and_no_judgment(self):
        state = a_chain_audit_state(
            current_chain_goal=a_chain_goal(),
            blocked_step_reason="destructive filesystem command: rm -rf",
        )

        result = abandon_chain(state)

        [chain] = result["completed_chains"]
        assert chain.blocked_reason == "destructive filesystem command: rm -rf"
        assert (chain.steps, chain.judge_result) == ([], None)
