from mcp_auditor.domain.models import (
    AttackChain,
    AuditCategory,
    AuditPayload,
    AuditReport,
    ProviderUsage,
    Severity,
    TestCase,
    ToolReport,
)
from mcp_auditor.domain.shown_response import MAX_SHOWN_LENGTH
from tests.unit.auditor.support.report_builders import (
    a_chain,
    a_chain_fail_result,
    a_fail_result,
    a_pass_result,
    a_report,
    a_run_command_tool_report,
    a_tool_definition,
    a_tool_report,
    a_two_tool_report,
)


def an_empty_report() -> AuditReport:
    return a_report(server_command="python honeypot_server.py", tool_reports=[])


def a_report_with_low_then_critical() -> AuditReport:
    results = [
        a_fail_result("tool_a", AuditCategory.INPUT_VALIDATION, Severity.LOW, "Weak validation"),
        a_fail_result("tool_a", AuditCategory.INJECTION, Severity.CRITICAL, "Command injection"),
    ]
    return a_report(
        server_command="python server.py",
        tool_reports=[a_tool_report("tool_a", results)],
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
        server_command="python server.py",
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
        server_command="python server.py",
        tool_reports=[a_tool_report("get_user", results)],
    )


def a_report_with_mapped_pass() -> AuditReport:
    results = [
        a_pass_result("get_user", AuditCategory.INJECTION),
    ]
    return a_report(
        server_command="python server.py",
        tool_reports=[a_tool_report("get_user", results)],
    )


def a_report_with_chain_injection_finding() -> AuditReport:
    chain = a_chain(
        category=AuditCategory.INJECTION,
        judge_result=a_chain_fail_result(category=AuditCategory.INJECTION),
    )
    tool_report = ToolReport(
        tool=a_tool_definition(name="get_user"),
        cases=[],
        chains=[chain],
    )
    return a_report(server_command="python server.py", tool_reports=[tool_report])


BLOCKED_CASE_REASON = "destructive filesystem command: rm -rf"
BLOCKED_CHAIN_REASON = "destructive SQL statement: drop table"


def a_report_with_a_blocked_case() -> AuditReport:
    return a_report(
        server_command="python server.py",
        tool_reports=[a_run_command_tool_report(cases=[a_blocked_case()])],
    )


def a_report_with_a_blocked_chain() -> AuditReport:
    return a_report(
        server_command="python server.py",
        tool_reports=[a_run_command_tool_report(chains=[a_blocked_chain()])],
    )


def a_report_with_a_blocked_case_and_a_blocked_chain() -> AuditReport:
    return a_report(
        server_command="python server.py",
        tool_reports=[
            a_run_command_tool_report(cases=[a_blocked_case()], chains=[a_blocked_chain()])
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


def a_report_with_an_unencodable_blocked_case() -> AuditReport:
    case = TestCase(
        payload=AuditPayload(
            category=AuditCategory.INPUT_VALIDATION,
            description="lone surrogate",
            arguments={"q": "\ud800"},
        ),
        blocked_reason="argument q holds a character that cannot be encoded as UTF-8",
    )
    return a_report(
        server_command="python server.py", tool_reports=[a_run_command_tool_report([case])]
    )


def a_blocked_chain() -> AttackChain:
    return a_chain(blocked_reason=BLOCKED_CHAIN_REASON)


def a_report_with_a_cut_response_on_get_user() -> AuditReport:
    report = a_two_tool_report()
    report.tool_reports[0].cases[0].response = "x" * (MAX_SHOWN_LENGTH + 1)
    return report


def a_report_throttled(throttled_requests: int) -> AuditReport:
    report = a_two_tool_report()
    report.provider_usage = ProviderUsage(
        input_tokens=15234, output_tokens=8421, throttled_requests=throttled_requests
    )
    return report
