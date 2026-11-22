from typing import Any

from mcp_auditor.domain.models import (
    AttackChain,
    AuditCategory,
    AuditPayload,
    ChainGoal,
    ChainStep,
    EvalVerdict,
    JudgeResult,
    Severity,
    ToolDefinition,
    ToolReport,
)


def a_tool_report(tool_name: str) -> ToolReport:
    return ToolReport(tool=a_tool(name=tool_name), cases=[])


def a_tool(name: str = "test_tool") -> ToolDefinition:
    return ToolDefinition(
        name=name, description="A test tool", input_schema={"type": "object", "properties": {}}
    )


def a_chain_audit_state(
    chain_budget: int = 2,
    current_chain_goal: ChainGoal | None = None,
    completed_chains: list[AttackChain] | None = None,
) -> dict[str, Any]:
    return {
        "current_tool": a_tool(),
        "chain_budget": chain_budget,
        "current_chain_goal": current_chain_goal,
        "completed_chains": completed_chains or [],
    }


def a_judged_chain() -> AttackChain:
    judge_result = JudgeResult(
        tool_name="test_tool",
        category=AuditCategory.INJECTION,
        arguments={"path": "/etc/passwd"},
        verdict=EvalVerdict.FAIL,
        justification="path traversal succeeded",
        severity=Severity.HIGH,
    )
    step = ChainStep(payload=_a_payload(), response="ok")
    return AttackChain(goal=a_chain_goal(), steps=[step], judge_result=judge_result)


def a_chain_goal() -> ChainGoal:
    return ChainGoal(
        description="probe then exploit", category=AuditCategory.INJECTION, first_step=_a_payload()
    )


def _a_payload() -> AuditPayload:
    return AuditPayload(
        category=AuditCategory.INJECTION, description="test step", arguments={"path": "/etc/passwd"}
    )
