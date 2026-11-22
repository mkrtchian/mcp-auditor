from collections.abc import AsyncIterator
from typing import Any

from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import AuditCategory, AuditPayload, ProviderUsage, TestCase
from mcp_auditor.domain.server_liveness import Relaunch, RelaunchCause, UnsentCause
from tests.unit.auditor.support.graph_builders import (
    a_fake_llm_for_single_tool_with_a_two_step_chain,
    a_graph,
    a_server_echoing,
    a_tool,
    an_initial_state,
)

type StreamEvent = tuple[tuple[str, ...], dict[str, Any]]

TOOL_AUDIT_NAMESPACE = ("audit_tool:1",)
CHAIN_AUDIT_NAMESPACE = ("chain_audit_tool:1",)
BLOCKED_REASON = "destructive filesystem command: rm -rf"


async def events_of_a_real_audit_with_one_chain() -> list[StreamEvent]:
    tool = a_tool(name="get_user")
    graph = a_graph(
        a_fake_llm_for_single_tool_with_a_two_step_chain(), a_server_echoing(tool, "user found")
    )
    stream: AsyncIterator[Any] = graph.astream(
        an_initial_state(chain_budget=1), stream_mode="updates", subgraphs=True
    )
    return [event async for event in stream]


def a_generation_event() -> StreamEvent:
    return (
        TOOL_AUDIT_NAMESPACE,
        {"generate_test_cases": {"pending_cases": [_a_case(), _a_case()]}},
    )


def an_execution_event_of_a_blocked_case(reason: str) -> StreamEvent:
    return (
        TOOL_AUDIT_NAMESPACE,
        {"execute_tool": {"processed_cases": [_a_case(reason)], "current_case": None}},
    )


def an_execution_event_of_a_sent_case() -> StreamEvent:
    return (
        TOOL_AUDIT_NAMESPACE,
        {"execute_tool": {"current_case": _a_case(), "pending_cases": []}},
    )


def an_unjudged_event(cause: MissedCallCause) -> StreamEvent:
    missed = MissedModelCall(
        tool_name="run_command", kind=ModelCallKind.JUDGMENT, cause=cause, detail="x"
    )
    return (
        TOOL_AUDIT_NAMESPACE,
        {"judge_response": {"processed_cases": [_a_case()], "missed_model_calls": [missed]}},
    )


def a_usage_event(namespace: tuple[str, ...], usage: ProviderUsage) -> StreamEvent:
    return (namespace, {"judge_response": {"provider_usage": [usage]}})


def a_case_not_sent_event(cause: UnsentCause) -> StreamEvent:
    update: dict[str, object] = {"pending_cases": [], "unsent_cases": 1, "unsent_cause": cause}
    return (TOOL_AUDIT_NAMESPACE, {"execute_tool": update})


def a_tool_report_event() -> StreamEvent:
    return ((), {"build_tool_report": {}})


def a_relaunch(cause: RelaunchCause, succeeded: bool) -> Relaunch:
    return Relaunch(
        tool_name="run_command", arguments={"command": "ls"}, cause=cause, succeeded=succeeded
    )


def _a_case(blocked_reason: str | None = None) -> TestCase:
    return TestCase(
        payload=AuditPayload(
            category=AuditCategory.INJECTION,
            description="wipe the filesystem",
            arguments={"command": "rm -rf /"},
        ),
        blocked_reason=blocked_reason,
    )
