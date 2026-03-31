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
    tool = a_tool(name=tool_name)
    case = TestCase(
        payload=AuditPayload(
            tool_name=tool_name,
            category=AuditCategory.INJECTION,
            description="test injection",
            arguments={"id": "1 OR 1=1"},
        ),
        response=response,
        error=error,
        eval_result=EvalResult(
            tool_name=tool_name,
            category=AuditCategory.INJECTION,
            payload={"id": "1 OR 1=1"},
            verdict=EvalVerdict.FAIL,
            justification="vulnerable",
            severity=Severity.HIGH,
        ),
    )
    return ToolReport(tool=tool, cases=[case])
