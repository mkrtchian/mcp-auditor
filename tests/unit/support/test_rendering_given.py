from mcp_auditor.domain.models import (
    AttackChain,
    AuditCategory,
    AuditPayload,
    AuditReport,
    ChainGoal,
    ChainStep,
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


def a_report_with_chain_finding() -> AuditReport:
    chain = a_chain(eval_result=a_chain_fail_result())
    tool_report = ToolReport(
        tool=a_tool_definition(name="get_user"),
        cases=[],
        chains=[chain],
    )
    return a_report(target="python server.py", tool_reports=[tool_report])


def a_report_with_chain_injection_finding() -> AuditReport:
    chain = a_chain(
        category=AuditCategory.INJECTION,
        eval_result=a_chain_fail_result(category=AuditCategory.INJECTION),
    )
    tool_report = ToolReport(
        tool=a_tool_definition(name="get_user"),
        cases=[],
        chains=[chain],
    )
    return a_report(target="python server.py", tool_reports=[tool_report])


def a_report_with_pass_case_and_fail_chain() -> AuditReport:
    pass_result = a_pass_result("get_user", AuditCategory.ERROR_HANDLING)
    chain = a_chain(eval_result=a_chain_fail_result())
    tool_report = ToolReport(
        tool=a_tool_definition(name="get_user"),
        cases=[
            TestCase(
                payload=AuditPayload(
                    tool_name="get_user",
                    category=AuditCategory.ERROR_HANDLING,
                    description="test",
                    arguments={"input": "test"},
                ),
                eval_result=pass_result,
            ),
        ],
        chains=[chain],
    )
    return a_report(target="python server.py", tool_reports=[tool_report])


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


def a_chain(
    description: str = "probe then exploit",
    category: AuditCategory = AuditCategory.INJECTION,
    eval_result: EvalResult | None = None,
) -> AttackChain:
    goal = ChainGoal(
        description=description,
        category=category,
        first_step=AuditPayload(
            tool_name="get_user",
            category=category,
            description="probe",
            arguments={"id": "1"},
        ),
    )
    steps = [
        ChainStep(
            payload=goal.first_step,
            response="user data with path /var/data",
            observation="Found internal path",
        ),
        ChainStep(
            payload=AuditPayload(
                tool_name="get_user",
                category=category,
                description="exploit",
                arguments={"id": "../../etc/passwd"},
            ),
            response="root:x:0:0",
            observation="Path traversal succeeded",
        ),
    ]
    return AttackChain(goal=goal, steps=steps, eval_result=eval_result)


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


def a_tool_definition(
    name: str = "test_tool",
    description: str = "A test tool",
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description=description,
        input_schema={"type": "object", "properties": {}},
    )


def a_chain_fail_result(
    tool_name: str = "get_user",
    category: AuditCategory = AuditCategory.INJECTION,
    severity: Severity = Severity.HIGH,
    justification: str = "Chain exploited",
) -> EvalResult:
    return EvalResult(
        tool_name=tool_name,
        category=category,
        payload={"path": "/etc/passwd"},
        verdict=EvalVerdict.FAIL,
        justification=justification,
        severity=severity,
    )
