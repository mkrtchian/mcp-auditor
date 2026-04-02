from typing import Any

from mcp_auditor.domain import (
    AttackContext,
    AuditCategory,
    AuditPayload,
    ChainGoal,
    ChainStep,
    EvalResult,
    EvalVerdict,
    Severity,
    StepObservation,
    ToolDefinition,
    ToolResponse,
)
from tests.fakes import FakeMCPClient


def a_tool(
    name: str = "file_manager",
    description: str = "Manages files",
    input_schema: dict[str, Any] | None = None,
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description=description,
        input_schema=input_schema or {"type": "object", "properties": {"path": {"type": "string"}}},
    )


def a_payload(
    tool_name: str = "file_manager",
    category: AuditCategory = AuditCategory.INJECTION,
    description: str = "test step",
    arguments: dict[str, Any] | None = None,
) -> AuditPayload:
    return AuditPayload(
        tool_name=tool_name,
        category=category,
        description=description,
        arguments=arguments or {"path": "/etc/passwd"},
    )


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


def a_fail_eval_result() -> EvalResult:
    return EvalResult(
        tool_name="t",
        category=AuditCategory.INJECTION,
        payload={"path": "/etc/passwd"},
        verdict=EvalVerdict.FAIL,
        justification="path traversal succeeded",
        severity=Severity.HIGH,
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
    judged_cases: list[Any] | None = None,
    attack_context: AttackContext | None = None,
    completed_chains: list[Any] | None = None,
) -> dict[str, Any]:
    return {
        "current_tool": tool or a_tool(),
        "judged_cases": judged_cases or [],
        "attack_context": attack_context or AttackContext(),
        "chain_budget": chain_budget,
        "max_chain_steps": max_chain_steps,
        "pending_chains": pending_chains or [],
        "current_chain_goal": current_chain_goal,
        "current_chain_steps": current_chain_steps or [],
        "current_step_payload": current_step_payload,
        "current_observation": current_observation,
        "completed_chains": completed_chains or [],
        "token_usage": [],
    }
