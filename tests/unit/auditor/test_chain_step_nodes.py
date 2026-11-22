from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.models import ModelCallKind, StepObservation, ToolResponse
from mcp_auditor.domain.server_liveness import UnsentCause
from mcp_auditor.graph.chain_nodes import (
    make_execute_step,
    make_observe_step,
    make_plan_step,
)
from tests.fakes import FakeLLM
from tests.unit.auditor.support.audited_servers import (
    a_server_losing_its_connection,
    a_server_taken_as_down,
)
from tests.unit.auditor.support.chain_states import (
    DEFAULT_TOOL_NAME,
    a_chain_audit_state,
    a_chain_goal,
    a_chain_step,
    a_fake_mcp_client,
    a_payload,
    a_provider_refusal,
    a_step_observation,
    a_tool,
    an_unreadable_answer,
)
from tests.unit.auditor.support.missed_chain_calls import (
    refused_call_recorded,
    unreadable_call_recorded,
)


class TestMakeExecuteStep:
    async def test_records_successful_response(self):
        tool = a_tool()
        payload = a_payload()
        client = a_fake_mcp_client(
            responses={tool.name: ToolResponse(content="found /data/projects")}
        )
        node = make_execute_step(AuditedServer(client))
        state = a_chain_audit_state(
            tool=tool,
            current_step_payload=payload,
        )

        result = await node(state)

        assert len(result["current_chain_steps"]) == 1
        step = result["current_chain_steps"][0]
        assert step.response == "found /data/projects"
        assert step.error is None

    async def test_records_error_response(self):
        tool = a_tool()
        payload = a_payload()
        client = a_fake_mcp_client(
            responses={tool.name: ToolResponse(content="denied", is_error=True)}
        )
        node = make_execute_step(AuditedServer(client))
        state = a_chain_audit_state(
            tool=tool,
            current_step_payload=payload,
        )

        result = await node(state)

        step = result["current_chain_steps"][0]
        assert step.error == "denied"
        assert step.response is None

    async def test_a_blocked_step_records_its_reason_and_is_not_sent(self):
        payload = a_payload(arguments={"path": "/tmp; rm -rf /"})
        client = a_fake_mcp_client()
        node = make_execute_step(AuditedServer(client))
        state = a_chain_audit_state(
            current_chain_goal=a_chain_goal(),
            current_chain_steps=[a_chain_step()],
            current_step_payload=payload,
        )

        result = await node(state)

        assert result["blocked_step_reason"] is not None
        assert "current_chain_steps" not in result
        assert client.calls == []

    async def test_a_step_not_sent_records_its_cause_and_no_step(self):
        server, client = await a_server_taken_as_down(a_tool())
        state = a_chain_audit_state(
            current_chain_goal=a_chain_goal(),
            current_chain_steps=[a_chain_step()],
            current_step_payload=a_payload(),
        )

        result = await make_execute_step(server)(state)

        assert result["unsent_step_cause"] is UnsentCause.SERVER_DOWN
        assert result["unsent_cause"] is UnsentCause.SERVER_DOWN
        assert "current_chain_steps" not in result
        assert len(client.calls) == 1

    async def test_a_step_followed_by_a_relaunch_is_recorded_and_cuts_the_chain(self):
        state = a_chain_audit_state(
            current_chain_goal=a_chain_goal(), current_step_payload=a_payload()
        )

        result = await make_execute_step(a_server_losing_its_connection(a_tool()))(state)

        [relaunch] = result["relaunches"]
        assert relaunch.tool_name == DEFAULT_TOOL_NAME
        assert result["chain_cut_by_relaunch"] is True
        assert len(result["current_chain_steps"]) == 1


class TestMakeObserveStep:
    async def test_updates_observation_and_returns_it(self):
        observation = StepObservation(
            observation="found path", should_continue=True, next_step_hint="try traversal"
        )
        llm = FakeLLM([observation])
        node = make_observe_step(llm)
        existing_step = a_chain_step(response="some data")
        goal = a_chain_goal()
        state = a_chain_audit_state(
            current_chain_goal=goal,
            current_chain_steps=[existing_step],
        )

        result = await node(state)

        latest = result["current_chain_steps"][-1]
        assert latest.observation == "found path"
        assert result["current_observation"].should_continue is True

    async def test_a_refused_observation_sends_the_chain_to_its_judgment(self):
        node = make_observe_step(FakeLLM([a_provider_refusal()]))
        state = a_chain_audit_state(
            current_chain_goal=a_chain_goal(),
            current_chain_steps=[a_chain_step()],
        )

        result = await node(state)

        refused_call_recorded(result, ModelCallKind.CHAIN_STEP_OBSERVATION)
        assert result["chain_model_call_missed"] is True

    async def test_an_unreadable_observation_sends_the_chain_to_its_judgment(self):
        unreadable = an_unreadable_answer()
        node = make_observe_step(FakeLLM([unreadable]))
        state = a_chain_audit_state(
            current_chain_goal=a_chain_goal(),
            current_chain_steps=[a_chain_step()],
        )

        result = await node(state)

        unreadable_call_recorded(result, ModelCallKind.CHAIN_STEP_OBSERVATION)
        assert result["provider_usage"] == [unreadable.usage]
        assert result["chain_usage"] == [unreadable.usage]
        assert result["chain_model_call_missed"] is True


class TestMakePlanStep:
    async def test_returns_next_payload(self):
        next_payload = a_payload(description="next step", arguments={"path": "../../../etc/shadow"})
        llm = FakeLLM([next_payload])
        node = make_plan_step(llm)
        goal = a_chain_goal()
        observation = a_step_observation(next_step_hint="try traversal")
        step = a_chain_step(observation="found path")
        state = a_chain_audit_state(
            current_chain_goal=goal,
            current_chain_steps=[step],
            current_observation=observation,
        )

        result = await node(state)

        assert result["current_step_payload"] == next_payload

    async def test_a_chain_step_planning_refusal_sends_the_chain_to_its_judgment(self):
        node = make_plan_step(FakeLLM([a_provider_refusal()]))
        state = a_chain_audit_state(
            current_chain_goal=a_chain_goal(),
            current_chain_steps=[a_chain_step()],
            current_observation=a_step_observation(),
        )

        result = await node(state)

        refused_call_recorded(result, ModelCallKind.CHAIN_STEP_PLANNING)
        assert result["chain_model_call_missed"] is True
