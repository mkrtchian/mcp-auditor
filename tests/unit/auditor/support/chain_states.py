from typing import Any

from mcp_auditor.domain.models import (
    AttackChain,
    AttackContext,
    AuditCategory,
    AuditPayload,
    ChainGoal,
    ChainStep,
    EvalVerdict,
    JudgeResult,
    Severity,
    StepObservation,
    TestCase,
    ToolDefinition,
    ToolResponse,
)
from mcp_auditor.domain.server_liveness import UnsentCause
from tests.fakes import FakeMCPClient

DEFAULT_TOOL_NAME = "file_manager"


def a_chain_goal(
    description: str = "probe then exploit",
    category: AuditCategory = AuditCategory.INJECTION,
    first_step: AuditPayload | None = None,
) -> ChainGoal:
    return ChainGoal(
        description=description,
        category=category,
        first_step=first_step or a_payload(),
    )


def a_single_step_case(response: str = "ok", error: str | None = None) -> TestCase:
    return TestCase(
        payload=a_payload(),
        response=response,
        error=error,
        judge_result=a_fail_judge_result(),
    )


def a_fail_judge_result() -> JudgeResult:
    return JudgeResult(
        tool_name="t",
        category=AuditCategory.INJECTION,
        arguments={"path": "/etc/passwd"},
        verdict=EvalVerdict.FAIL,
        justification="path traversal succeeded",
        severity=Severity.HIGH,
    )


def a_blocked_single_step_case(
    reason: str = "destructive filesystem command: rm -rf",
) -> TestCase:
    return TestCase(payload=a_payload(arguments={"path": "1; rm -rf /"}), blocked_reason=reason)


def a_payload(
    category: AuditCategory = AuditCategory.INJECTION,
    description: str = "test step",
    arguments: dict[str, Any] | None = None,
) -> AuditPayload:
    return AuditPayload(
        category=category,
        description=description,
        arguments=arguments or {"path": "/etc/passwd"},
    )


def a_chain_step(
    payload: AuditPayload | None = None,
    response: str | None = "ok",
    error: str | None = None,
    observation: str = "",
) -> ChainStep:
    return ChainStep(
        payload=payload or a_payload(),
        response=response,
        error=error,
        observation=observation,
    )


def a_step_observation(
    observation: str = "interesting",
    should_continue: bool = True,
    next_step_hint: str = "",
) -> StepObservation:
    return StepObservation(
        observation=observation,
        should_continue=should_continue,
        next_step_hint=next_step_hint,
    )


def a_fake_mcp_client(
    tools: list[ToolDefinition] | None = None,
    responses: dict[str, ToolResponse] | None = None,
) -> FakeMCPClient:
    return FakeMCPClient(tools or [a_tool()], responses)


def a_tool(
    name: str = DEFAULT_TOOL_NAME,
    description: str = "Manages files",
    input_schema: dict[str, Any] | None = None,
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description=description,
        input_schema=input_schema or {"type": "object", "properties": {"path": {"type": "string"}}},
    )


def a_chain_audit_state(
    tool: ToolDefinition | None = None,
    pending_chains: list[ChainGoal] | None = None,
    current_chain_goal: ChainGoal | None = None,
    current_chain_steps: list[ChainStep] | None = None,
    current_step_payload: AuditPayload | None = None,
    current_observation: StepObservation | None = None,
    chain_budget: int = 2,
    max_chain_steps: int = 5,
    processed_cases: list[TestCase] | None = None,
    attack_context: AttackContext | None = None,
    completed_chains: list[AttackChain] | None = None,
    blocked_step_reason: str | None = None,
    chain_model_call_missed: bool = False,
    chain_cut_by_relaunch: bool = False,
    unsent_step_cause: UnsentCause | None = None,
) -> dict[str, Any]:
    return {
        "current_tool": tool or a_tool(),
        "processed_cases": processed_cases or [],
        "attack_context": attack_context or AttackContext(),
        "chain_budget": chain_budget,
        "max_chain_steps": max_chain_steps,
        "pending_chains": pending_chains or [],
        "current_chain_goal": current_chain_goal,
        "current_chain_steps": current_chain_steps or [],
        "current_step_payload": current_step_payload,
        "current_observation": current_observation,
        "completed_chains": completed_chains or [],
        "blocked_step_reason": blocked_step_reason,
        "chain_model_call_missed": chain_model_call_missed,
        "chain_cut_by_relaunch": chain_cut_by_relaunch,
        "unsent_step_cause": unsent_step_cause,
        "provider_usage": [],
    }
