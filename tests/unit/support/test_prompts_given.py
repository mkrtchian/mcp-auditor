from typing import Any

from mcp_auditor.domain import (
    AuditCategory,
    AuditPayload,
    EvalResult,
    EvalVerdict,
    Severity,
    TestCase,
    ToolDefinition,
    ToolReport,
)


def a_tool(
    name: str = "get_user",
    description: str = "Fetch user by ID",
    input_schema: dict[str, Any] | None = None,
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description=description,
        input_schema=input_schema or {},
    )


def a_test_case(
    description: str = "test description",
    response: str | None = None,
    error: str | None = None,
) -> TestCase:
    return TestCase(
        payload=AuditPayload(
            tool_name="get_user",
            category=AuditCategory.INJECTION,
            description=description,
            arguments={"id": "1 OR 1=1"},
        ),
        response=response,
        error=error,
    )


def a_tool_report(
    tool_name: str = "get_user",
    response: str | None = "some response",
    error: str | None = None,
) -> ToolReport:
    case = TestCase(
        payload=AuditPayload(
            tool_name=tool_name,
            category=AuditCategory.INJECTION,
            description="test injection",
            arguments={"id": "1 OR 1=1"},
        ),
        response=response,
        error=error,
        eval_result=_a_failing_eval_result(tool_name),
    )
    return ToolReport(tool=a_tool(name=tool_name), cases=[case])


def _a_failing_eval_result(tool_name: str) -> EvalResult:
    return EvalResult(
        tool_name=tool_name,
        category=AuditCategory.INJECTION,
        payload={"id": "1 OR 1=1"},
        verdict=EvalVerdict.FAIL,
        justification="vulnerable",
        severity=Severity.HIGH,
    )
