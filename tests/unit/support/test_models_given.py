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
        "tool_name": "test_tool",
        "category": AuditCategory.INPUT_VALIDATION,
        "description": "test payload",
        "arguments": {},
    }
    return AuditPayload(**(defaults | overrides))


def a_report_with_finding(severity: Severity) -> AuditReport:
    result = EvalResult(
        tool_name="t",
        category=AuditCategory.INJECTION,
        payload={},
        verdict=EvalVerdict.FAIL,
        justification="vuln",
        severity=severity,
    )
    case = TestCase(
        payload=AuditPayload(
            tool_name="t",
            category=AuditCategory.INJECTION,
            description="test",
            arguments={},
        ),
        eval_result=result,
    )
    tool = ToolDefinition(name="t", description="t", input_schema={})
    return AuditReport(
        target="test",
        tool_reports=[ToolReport(tool=tool, cases=[case])],
        token_usage=TokenUsage(),
    )
