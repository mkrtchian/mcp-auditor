from mcp_auditor.domain.execution import ExecutionRecord
from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import (
    AttackChain,
    AuditCategory,
    AuditPayload,
    AuditReport,
    ChainGoal,
    ChainStep,
    CoverageGap,
    EvalVerdict,
    JudgeResult,
    ProviderUsage,
    Severity,
    TestCase,
    ToolDefinition,
    ToolReport,
)


def a_report_with_chain_finding() -> AuditReport:
    chain = a_chain(judge_result=a_chain_fail_result())
    tool_report = ToolReport(
        tool=a_tool_definition(name="get_user"),
        cases=[],
        chains=[chain],
    )
    return a_report(server_command="python server.py", tool_reports=[tool_report])


def a_report_with_pass_case_and_fail_chain() -> AuditReport:
    pass_result = a_pass_result("get_user", AuditCategory.ERROR_HANDLING)
    chain = a_chain(judge_result=a_chain_fail_result())
    tool_report = ToolReport(
        tool=a_tool_definition(name="get_user"),
        cases=[
            TestCase(
                payload=AuditPayload(
                    category=AuditCategory.ERROR_HANDLING,
                    description="test",
                    arguments={"input": "test"},
                ),
                judge_result=pass_result,
            ),
        ],
        chains=[chain],
    )
    return a_report(server_command="python server.py", tool_reports=[tool_report])


def a_report_with_a_coverage_gap_on_get_user() -> AuditReport:
    report = a_two_tool_report()
    report.tool_reports[0].coverage_gap = CoverageGap(
        requested_cases=10,
        received_cases=7,
        missing_categories=[AuditCategory.INJECTION, AuditCategory.RESOURCE_ABUSE],
    )
    return report


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
        server_command="python honeypot_server.py",
        tool_reports=[
            a_tool_report("get_user", get_user_results),
            a_tool_report("list_items", list_items_results),
        ],
        provider_usage=ProviderUsage(input_tokens=15234, output_tokens=8421),
    )


REFUSAL_MESSAGE = "Invalid prompt: flagged as potentially violating our usage policy"


def a_report_with_a_refused_judgment_on_get_user() -> AuditReport:
    report = a_two_tool_report()
    report.missed_model_calls = [
        MissedModelCall(
            tool_name="get_user",
            kind=ModelCallKind.JUDGMENT,
            cause=MissedCallCause.PROVIDER_REFUSAL,
            detail=REFUSAL_MESSAGE,
        )
    ]
    return report


def a_run_command_tool_report(
    cases: list[TestCase] | None = None,
    chains: list[AttackChain] | None = None,
) -> ToolReport:
    return ToolReport(
        tool=a_tool_definition(name="run_command"),
        cases=cases or [],
        chains=chains or [],
    )


def a_report(
    server_command: str,
    tool_reports: list[ToolReport],
    provider_usage: ProviderUsage | None = None,
    execution: ExecutionRecord | None = None,
) -> AuditReport:
    return AuditReport(
        server_command=server_command,
        tool_reports=tool_reports,
        provider_usage=provider_usage or ProviderUsage(),
        execution=execution,
    )


def a_tool_report(
    tool_name: str,
    results: list[JudgeResult],
) -> ToolReport:
    cases = [
        TestCase(
            payload=AuditPayload(
                category=r.category,
                description="test",
                arguments=r.arguments,
            ),
            judge_result=r,
        )
        for r in results
    ]
    return ToolReport(
        tool=a_tool_definition(name=tool_name, description=f"The {tool_name} tool"),
        cases=cases,
    )


def a_chain(
    judge_result: JudgeResult | None = None,
    blocked_reason: str | None = None,
) -> AttackChain:
    goal = ChainGoal(
        description="probe then exploit",
        category=AuditCategory.INJECTION,
        first_step=AuditPayload(
            category=AuditCategory.INJECTION,
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
                category=AuditCategory.INJECTION,
                description="exploit",
                arguments={"id": "../../etc/passwd"},
            ),
            response="root:x:0:0",
            observation="Path traversal succeeded",
        ),
    ]
    return AttackChain(
        goal=goal, steps=steps, judge_result=judge_result, blocked_reason=blocked_reason
    )


def a_fail_result(
    tool_name: str,
    category: AuditCategory,
    severity: Severity,
    justification: str = "Vulnerable to attack",
) -> JudgeResult:
    return JudgeResult(
        tool_name=tool_name,
        category=category,
        arguments={"input": "malicious"},
        verdict=EvalVerdict.FAIL,
        justification=justification,
        severity=severity,
    )


def a_pass_result(
    tool_name: str,
    category: AuditCategory,
) -> JudgeResult:
    return JudgeResult(
        tool_name=tool_name,
        category=category,
        arguments={"input": "test"},
        verdict=EvalVerdict.PASS,
        justification="Handled correctly",
        severity=Severity.LOW,
    )


def a_passing_case(tool_name: str) -> TestCase:
    return _a_test_case(tool_name, AuditCategory.INJECTION, EvalVerdict.PASS, "ok", Severity.LOW)


def a_failing_case(
    tool_name: str,
    severity: Severity,
    category: AuditCategory,
    justification: str,
) -> TestCase:
    return _a_test_case(tool_name, category, EvalVerdict.FAIL, justification, severity)


def _a_test_case(
    tool_name: str,
    category: AuditCategory,
    verdict: EvalVerdict,
    justification: str,
    severity: Severity,
) -> TestCase:
    return TestCase(
        payload=AuditPayload(
            category=category,
            description="test",
            arguments={},
        ),
        judge_result=JudgeResult(
            tool_name=tool_name,
            category=category,
            arguments={},
            verdict=verdict,
            justification=justification,
            severity=severity,
        ),
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


def a_chain_fail_result() -> JudgeResult:
    return JudgeResult(
        tool_name="get_user",
        category=AuditCategory.INJECTION,
        arguments={"path": "/etc/passwd"},
        verdict=EvalVerdict.FAIL,
        justification="Chain exploited",
        severity=Severity.HIGH,
    )
