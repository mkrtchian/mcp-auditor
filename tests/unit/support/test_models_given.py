from typing import Any

from mcp_auditor.domain import (
    AuditCategory,
    AuditPayload,
    AuditReport,
    EvalResult,
    EvalVerdict,
    Severity,
    TestCase,
    TokenUsage,
    ToolDefinition,
    ToolReport,
)


def a_tool(
    name: str = "test_tool",
    input_schema: dict[str, Any] | None = None,
) -> ToolDefinition:
    return ToolDefinition(name=name, description="desc", input_schema=input_schema or {})


def a_payload(**overrides: Any) -> AuditPayload:
    defaults: dict[str, Any] = {
        "category": AuditCategory.INPUT_VALIDATION,
        "description": "test payload",
        "arguments": {},
    }
    return AuditPayload(**(defaults | overrides))


def an_eval_result(**overrides: Any) -> EvalResult:
    defaults: dict[str, Any] = {
        "tool_name": "t",
        "category": AuditCategory.INJECTION,
        "payload": {},
        "verdict": EvalVerdict.FAIL,
        "justification": "vuln",
        "severity": Severity.HIGH,
    }
    return EvalResult(**(defaults | overrides))


def a_report_with_finding(severity: Severity) -> AuditReport:
    case = TestCase(
        payload=a_payload(category=AuditCategory.INJECTION),
        eval_result=an_eval_result(severity=severity),
    )
    return AuditReport(
        target="test",
        tool_reports=[ToolReport(tool=a_tool(), cases=[case])],
        token_usage=TokenUsage(),
    )
