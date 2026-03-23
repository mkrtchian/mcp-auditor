from mcp_auditor.domain.models import (
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


def an_empty_report() -> AuditReport:
    return a_report(
        target="python dummy_server.py",
        tool_reports=[],
        input_tokens=0,
        output_tokens=0,
    )


def a_report_with_low_then_critical() -> AuditReport:
    results = [
        a_fail_result("tool_a", AuditCategory.INPUT_VALIDATION, Severity.LOW, "Weak validation"),
        a_fail_result("tool_a", AuditCategory.INJECTION, Severity.CRITICAL, "Command injection"),
    ]
    return a_report(
        target="python server.py",
        tool_reports=[a_tool_report("tool_a", results)],
    )


def a_two_tool_report() -> AuditReport:
    get_user_results = [
        a_fail_result(
            "get_user",
            AuditCategory.INPUT_VALIDATION,
            Severity.HIGH,
            justification="No input length validation",
        ),
        a_fail_result(
            "get_user",
            AuditCategory.INJECTION,
            Severity.CRITICAL,
            justification="SQL injection via user_id parameter",
        ),
    ]
    list_items_results = [
        a_pass_result("list_items", AuditCategory.ERROR_HANDLING),
    ]
    return a_report(
        target="python dummy_server.py",
        tool_reports=[
            a_tool_report("get_user", get_user_results),
            a_tool_report("list_items", list_items_results),
        ],
        input_tokens=15234,
        output_tokens=8421,
    )


def a_report(
    target: str,
    tool_reports: list[ToolReport],
    input_tokens: int = 0,
    output_tokens: int = 0,
) -> AuditReport:
    return AuditReport(
        target=target,
        tool_reports=tool_reports,
        token_usage=TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens),
    )


def a_tool_report(
    tool_name: str,
    results: list[EvalResult],
) -> ToolReport:
    cases = [
        TestCase(
            payload=AuditPayload(
                tool_name=r.tool_name,
                category=r.category,
                description="test",
                arguments=r.payload,
            ),
            eval_result=r,
        )
        for r in results
    ]
    return ToolReport(
        tool=a_tool_definition(name=tool_name, description=f"The {tool_name} tool"),
        cases=cases,
    )


def a_fail_result(
    tool_name: str,
    category: AuditCategory,
    severity: Severity,
    justification: str = "Vulnerable to attack",
) -> EvalResult:
    return EvalResult(
        tool_name=tool_name,
        category=category,
        payload={"input": "malicious"},
        verdict=EvalVerdict.FAIL,
        justification=justification,
        severity=severity,
    )


def a_pass_result(
    tool_name: str,
    category: AuditCategory,
) -> EvalResult:
    return EvalResult(
        tool_name=tool_name,
        category=category,
        payload={"input": "test"},
        verdict=EvalVerdict.PASS,
        justification="Handled correctly",
        severity=Severity.LOW,
    )


def a_report_with_injection_finding() -> AuditReport:
    results = [
        a_fail_result(
            "get_user",
            AuditCategory.INJECTION,
            Severity.HIGH,
            justification="SQL injection via user_id parameter",
        ),
    ]
    return a_report(
        target="python server.py",
        tool_reports=[a_tool_report("get_user", results)],
    )


def a_report_with_unmapped_finding() -> AuditReport:
    results = [
        a_fail_result(
            "get_user",
            AuditCategory.INPUT_VALIDATION,
            Severity.MEDIUM,
            justification="No input length validation",
        ),
    ]
    return a_report(
        target="python server.py",
        tool_reports=[a_tool_report("get_user", results)],
    )


def a_report_with_mapped_pass() -> AuditReport:
    results = [
        a_pass_result("get_user", AuditCategory.INJECTION),
    ]
    return a_report(
        target="python server.py",
        tool_reports=[a_tool_report("get_user", results)],
    )


def a_tool_definition(
    name: str = "test_tool",
    description: str = "A test tool",
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description=description,
        input_schema={"type": "object", "properties": {}},
    )
