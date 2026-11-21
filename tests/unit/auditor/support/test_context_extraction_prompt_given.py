from mcp_auditor.domain import (
    AuditCategory,
    AuditPayload,
    EvalVerdict,
    JudgeResult,
    Severity,
    TestCase,
    ToolDefinition,
    ToolReport,
)


def a_tool_report(
    tool_name: str = "get_user",
    response: str | None = "some response",
    error: str | None = None,
) -> ToolReport:
    case = TestCase(
        payload=AuditPayload(
            category=AuditCategory.INJECTION,
            description="test injection",
            arguments={"id": "1 OR 1=1"},
        ),
        response=response,
        error=error,
        judge_result=_a_failing_judge_result(tool_name),
    )
    tool = ToolDefinition(name=tool_name, description="Fetch user by ID", input_schema={})
    return ToolReport(tool=tool, cases=[case])


def a_tool_report_with_a_blocked_case() -> ToolReport:
    report = a_tool_report()
    return report.model_copy(update={"cases": [*report.cases, _a_blocked_case()]})


def a_tool_report_with_only_a_blocked_case() -> ToolReport:
    return a_tool_report().model_copy(update={"cases": [_a_blocked_case()]})


def _a_blocked_case() -> TestCase:
    return TestCase(
        payload=AuditPayload(
            category=AuditCategory.INJECTION,
            description="destructive payload that was never sent",
            arguments={"id": "1; rm -rf /"},
        ),
        blocked_reason="destructive filesystem command: rm -rf",
    )


def _a_failing_judge_result(tool_name: str) -> JudgeResult:
    return JudgeResult(
        tool_name=tool_name,
        category=AuditCategory.INJECTION,
        arguments={"id": "1 OR 1=1"},
        verdict=EvalVerdict.FAIL,
        justification="vulnerable",
        severity=Severity.HIGH,
    )
