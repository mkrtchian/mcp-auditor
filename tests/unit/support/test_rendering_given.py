from mcp_auditor.domain.models import (
    AttackChain,
    AuditCategory,
    AuditPayload,
    AuditReport,
    AuditStep,
    ChainGoal,
    ChainStep,
    CoverageGap,
    EvalResult,
    EvalVerdict,
    ExecutionRecord,
    ExecutionRegime,
    ProviderUsage,
    RefusedStep,
    Severity,
    TestCase,
    ToolDefinition,
    ToolReport,
)


def an_empty_report() -> AuditReport:
    return a_report(target="python honeypot_server.py", tool_reports=[])


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
        target="python honeypot_server.py",
        tool_reports=[
            a_tool_report("get_user", get_user_results),
            a_tool_report("list_items", list_items_results),
        ],
        provider_usage=ProviderUsage(input_tokens=15234, output_tokens=8421),
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


BLOCKED_CASE_REASON = "destructive filesystem command: rm -rf"
BLOCKED_CHAIN_REASON = "destructive SQL statement: drop table"


def a_report_with_a_blocked_case() -> AuditReport:
    return a_report(
        target="python server.py",
        tool_reports=[_a_tool_report_with_blocked(cases=[a_blocked_case()])],
    )


def a_report_with_a_blocked_chain() -> AuditReport:
    return a_report(
        target="python server.py",
        tool_reports=[_a_tool_report_with_blocked(chains=[a_blocked_chain()])],
    )


def a_report_with_a_blocked_case_and_a_blocked_chain() -> AuditReport:
    return a_report(
        target="python server.py",
        tool_reports=[
            _a_tool_report_with_blocked(cases=[a_blocked_case()], chains=[a_blocked_chain()])
        ],
    )


def a_blocked_case() -> TestCase:
    return TestCase(
        payload=AuditPayload(
            category=AuditCategory.INJECTION,
            description="wipe the filesystem",
            arguments={"command": "rm -rf /"},
        ),
        blocked_reason=BLOCKED_CASE_REASON,
    )


def a_blocked_chain() -> AttackChain:
    return a_chain(blocked_reason=BLOCKED_CHAIN_REASON)


def _a_tool_report_with_blocked(
    cases: list[TestCase] | None = None,
    chains: list[AttackChain] | None = None,
) -> ToolReport:
    return ToolReport(
        tool=a_tool_definition(name="run_command"),
        cases=cases or [],
        chains=chains or [],
    )


FULL_DIGEST = "sha256:abc123def4567890abc123def4567890abc123def4567890abc123def4567890"


def a_confined_record(
    image_digest: str | None = FULL_DIGEST,
    writable_paths: list[str] | None = None,
    read_only_paths: list[str] | None = None,
    oom_killed: bool | None = False,
) -> ExecutionRecord:
    return ExecutionRecord(
        regime=ExecutionRegime.CONFINED,
        image="node:24-bookworm-slim",
        image_digest=image_digest,
        writable_paths=writable_paths if writable_paths is not None else ["/tmp/sandbox"],
        read_only_paths=read_only_paths if read_only_paths is not None else [],
        oom_killed=oom_killed,
    )


def a_report_with_a_coverage_gap_on_get_user() -> AuditReport:
    report = a_two_tool_report()
    report.tool_reports[0].coverage_gap = CoverageGap(
        requested_cases=10,
        received_cases=7,
        missing_categories=[AuditCategory.INJECTION, AuditCategory.RESOURCE_ABUSE],
    )
    return report


REFUSAL_MESSAGE = "Invalid prompt: flagged as potentially violating our usage policy"


def a_report_with_a_refused_judgment_on_get_user() -> AuditReport:
    report = a_two_tool_report()
    report.refused_steps = [
        RefusedStep(tool_name="get_user", step=AuditStep.JUDGMENT, provider_message=REFUSAL_MESSAGE)
    ]
    return report


def a_report_with_an_unjudged_case() -> AuditReport:
    unjudged = TestCase(
        payload=AuditPayload(
            category=AuditCategory.INJECTION,
            description="shell metacharacters",
            arguments={"command": "ls; cat /etc/shadow"},
        ),
    )
    return a_report(
        target="python server.py",
        tool_reports=[_a_tool_report_with_blocked(cases=[unjudged])],
    )


def a_report_with_an_unjudged_chain() -> AuditReport:
    return a_report(
        target="python server.py",
        tool_reports=[_a_tool_report_with_blocked(chains=[a_chain()])],
    )


def a_report_with_execution(record: ExecutionRecord) -> AuditReport:
    return a_report(target="npx server", tool_reports=[], execution=record)


def a_report(
    target: str,
    tool_reports: list[ToolReport],
    provider_usage: ProviderUsage | None = None,
    execution: ExecutionRecord | None = None,
) -> AuditReport:
    return AuditReport(
        target=target,
        tool_reports=tool_reports,
        provider_usage=provider_usage or ProviderUsage(),
        execution=execution,
    )


def a_tool_report(
    tool_name: str,
    results: list[EvalResult],
) -> ToolReport:
    cases = [
        TestCase(
            payload=AuditPayload(
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
    blocked_reason: str | None = None,
) -> AttackChain:
    goal = ChainGoal(
        description=description,
        category=category,
        first_step=AuditPayload(
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
                category=category,
                description="exploit",
                arguments={"id": "../../etc/passwd"},
            ),
            response="root:x:0:0",
            observation="Path traversal succeeded",
        ),
    ]
    return AttackChain(
        goal=goal, steps=steps, eval_result=eval_result, blocked_reason=blocked_reason
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
