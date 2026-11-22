from typing import Any

from langgraph.graph import END

import tests.unit.auditor.support.test_execute_and_judge_then as then
from mcp_auditor.domain.audited_server import AuditedServer
from mcp_auditor.domain.model_calls import ModelCallKind
from mcp_auditor.domain.models import EvalVerdict, JudgeResult, Severity, ToolResponse
from mcp_auditor.domain.server_liveness import Relaunch, RelaunchCause, UnsentCause
from mcp_auditor.graph.nodes import make_execute_tool, make_judge_response, route_after_execute
from tests.fakes import FakeLLM, FakeMCPClient
from tests.fakes.mcp_client import a_lost_connection_response
from tests.unit.auditor.support.audited_servers import a_server_taken_as_down
from tests.unit.auditor.support.graph_builders import a_judgment, a_payload, a_test_case, a_tool
from tests.unit.auditor.support.model_failures import a_provider_refusal, a_recorded_refusal


class TestExecuteTool:
    async def test_records_the_response_of_the_current_tool(self):
        tool = a_tool(name="read_file")
        case = a_test_case()
        client = FakeMCPClient(
            [tool], responses={"read_file": ToolResponse(content="read_file was called")}
        )
        node = make_execute_tool(AuditedServer(client))

        result = await node({"pending_cases": [case], "current_tool": tool})

        assert result["current_case"].response == "read_file was called"
        assert result["current_case"].blocked_reason is None
        assert result["pending_cases"] == []

    async def test_error(self):
        tool = a_tool(name="my_tool")
        case = a_test_case()
        client = FakeMCPClient(
            [tool],
            responses={"my_tool": ToolResponse(content="not found", is_error=True)},
        )
        node = make_execute_tool(AuditedServer(client))

        result = await node({"pending_cases": [case], "current_tool": tool})

        then.current_case_has_error(result, "not found")

    async def test_records_a_destructive_case_as_blocked_without_calling_the_server(self):
        tool = a_tool(name="run_command")
        case = a_test_case(payload=a_payload(arguments={"command": "rm -rf /"}))
        client = FakeMCPClient([tool])
        node = make_execute_tool(AuditedServer(client))

        result = await node({"pending_cases": [case], "current_tool": tool})

        [blocked] = result["processed_cases"]
        assert blocked.blocked_reason is not None
        assert client.calls == []

    async def test_blocked_case_holds_no_verdict_and_no_server_output(self):
        tool = a_tool(name="run_command")
        case = a_test_case(payload=a_payload(arguments={"command": "rm -rf /"}))
        node = make_execute_tool(AuditedServer(FakeMCPClient([tool])))

        result = await node({"pending_cases": [case], "current_tool": tool})

        blocked = result["processed_cases"][0]
        assert blocked.judge_result is None
        assert blocked.response is None
        assert blocked.error is None
        assert result["current_case"] is None

    async def test_a_case_not_sent_is_counted_apart_and_not_judged(self):
        tool = a_tool(name="read_file")
        server, client = await a_server_taken_as_down(tool)
        node = make_execute_tool(server)
        state: dict[str, Any] = {"pending_cases": [a_test_case()], "current_tool": tool}

        result = await node(state)

        assert "processed_cases" not in result
        assert result["unsent_cases"] == 1
        assert result["unsent_cause"] is UnsentCause.SERVER_DOWN
        assert (result["current_case"], result["pending_cases"]) == (None, [])
        assert len(client.calls) == 1

    async def test_a_case_followed_by_a_relaunch_keeps_its_error_and_the_relaunch(self):
        tool = a_tool(name="read_file")
        client = FakeMCPClient([tool], responses={"read_file": a_lost_connection_response()})
        node = make_execute_tool(AuditedServer(client))
        case = a_test_case()
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
        tool = a_tool(name="read_file")
        node = make_execute_tool(AuditedServer(FakeMCPClient([tool])))
        state: dict[str, Any] = {
            "pending_cases": [a_test_case()],
            "current_tool": tool,
            "unsent_cause": UnsentCause.TOOL_TIMING_OUT,
        }

        result = await node(state)

        assert "unsent_cause" not in result


class TestJudgeResponse:
    async def test_stamps_identity_and_uses_judgment(self):
        judgment = a_judgment(verdict=EvalVerdict.FAIL, severity=Severity.HIGH)
        llm = FakeLLM([judgment])
        node = make_judge_response(llm)
        case = a_test_case(response="some output")
        tool = a_tool(name="read_file")

        result = await node({"current_case": case, "processed_cases": [], "current_tool": tool})

        judge_result = JudgeResult(
            tool_name="read_file",
            category=case.payload.category,
            arguments=case.payload.arguments,
            verdict=judgment.verdict,
            justification=judgment.justification,
            severity=judgment.severity,
        )
        assert result["processed_cases"] == [case.model_copy(update={"judge_result": judge_result})]

    async def test_a_refused_judgment_leaves_the_case_unjudged(self):
        refusal = a_provider_refusal()
        node = make_judge_response(FakeLLM([refusal]))
        case = a_test_case(response="some output")
        tool = a_tool(name="read_file")

        result = await node({"current_case": case, "processed_cases": [], "current_tool": tool})

        assert result["processed_cases"] == [case]
        assert result["processed_cases"][0].judge_result is None
        assert result["current_case"] is None
        assert result["missed_model_calls"] == [
            a_recorded_refusal("read_file", ModelCallKind.JUDGMENT)
        ]
        assert result["provider_usage"] == [refusal.usage]
        assert result["judge_usage"] == [refusal.usage]
        assert "chain_usage" not in result


class TestRouteAfterExecute:
    def test_judges_an_executed_case(self):
        state: dict[str, Any] = {
            "current_case": a_test_case(response="output"),
            "pending_cases": [],
        }
        assert route_after_execute(state) == "judge_response"

    def test_moves_to_the_next_case_after_a_block(self):
        state: dict[str, Any] = {"current_case": None, "pending_cases": [a_test_case()]}
        assert route_after_execute(state) == "execute_tool"

    def test_ends_when_a_block_was_the_last_case(self):
        state: dict[str, Any] = {"current_case": None, "pending_cases": []}
        assert route_after_execute(state) == END
