from io import StringIO

from rich.console import Console

from mcp_auditor.console import AuditDisplay
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


def a_display() -> tuple[AuditDisplay, StringIO]:
    buffer = StringIO()
    console = Console(file=buffer, force_terminal=True)
    return AuditDisplay(console=console), buffer


def a_ci_display() -> tuple[AuditDisplay, StringIO]:
    buffer = StringIO()
    console = Console(file=buffer, force_terminal=False, no_color=True)
    return AuditDisplay(console=console, ci_mode=True), buffer


def a_fail_result(
    tool_name: str,
    category: AuditCategory,
    severity: Severity,
    justification: str,
) -> EvalResult:
    return EvalResult(
        tool_name=tool_name,
        category=category,
        payload={},
        verdict=EvalVerdict.FAIL,
        justification=justification,
        severity=severity,
    )


def a_report_with_one_pass_plus_failures(
    failures_per_tool: dict[str, list[tuple[Severity, AuditCategory, str]]],
) -> AuditReport:
    tool_reports: list[ToolReport] = []
    for tool_name, failures in failures_per_tool.items():
        cases = [
            _a_test_case(
                tool_name, AuditCategory.INJECTION, EvalVerdict.PASS, "ok", Severity.LOW,
            ),
        ]
        for severity, category, justification in failures:
            cases.append(
                _a_test_case(tool_name, category, EvalVerdict.FAIL, justification, severity),
            )
        tool_reports.append(
            ToolReport(
                tool=ToolDefinition(name=tool_name, description="", input_schema={}),
                cases=cases,
            )
        )
    return _a_report(tool_reports)


def a_report_with_n_results(pass_count: int, fail_count: int) -> AuditReport:
    cases: list[TestCase] = []
    for _i in range(pass_count):
        cases.append(
            _a_test_case("tool_a", AuditCategory.INJECTION, EvalVerdict.PASS, "ok", Severity.LOW)
        )
    for _i in range(fail_count):
        cases.append(
            _a_test_case(
                "tool_a", AuditCategory.INJECTION, EvalVerdict.FAIL, "vuln", Severity.MEDIUM,
            )
        )
    return _a_report([
        ToolReport(
            tool=ToolDefinition(name="tool_a", description="", input_schema={}),
            cases=cases,
        )
    ])


def dry_run_payloads() -> list[AuditPayload]:
    return [
        AuditPayload(
            tool_name="get_user",
            category=AuditCategory.INJECTION,
            description="SQL injection",
            arguments={"id": "1; DROP TABLE users"},
        ),
        AuditPayload(
            tool_name="get_user",
            category=AuditCategory.INPUT_VALIDATION,
            description="Empty input",
            arguments={"id": ""},
        ),
    ]


def a_report_with_two_tools() -> AuditReport:
    return AuditReport(
        target="python server.py",
        tool_reports=[
            ToolReport(
                tool=ToolDefinition(name="get_user", description="", input_schema={}),
                cases=[
                    _a_test_case(
                        "get_user", AuditCategory.INJECTION, EvalVerdict.PASS, "ok", Severity.LOW,
                    ),
                ],
            ),
            ToolReport(
                tool=ToolDefinition(name="list_items", description="", input_schema={}),
                cases=[
                    _a_test_case(
                        "list_items", AuditCategory.INPUT_VALIDATION,
                        EvalVerdict.FAIL, "bad", Severity.HIGH,
                    ),
                ],
            ),
        ],
        token_usage=TokenUsage(input_tokens=1234, output_tokens=567),
    )


def _a_test_case(
    tool_name: str,
    category: AuditCategory,
    verdict: EvalVerdict,
    justification: str,
    severity: Severity,
) -> TestCase:
    return TestCase(
        payload=AuditPayload(
            tool_name=tool_name,
            category=category,
            description="test",
            arguments={},
        ),
        eval_result=EvalResult(
            tool_name=tool_name,
            category=category,
            payload={},
            verdict=verdict,
            justification=justification,
            severity=severity,
        ),
    )


def _a_report(tool_reports: list[ToolReport]) -> AuditReport:
    return AuditReport(
        target="python server.py",
        tool_reports=tool_reports,
        token_usage=TokenUsage(input_tokens=100, output_tokens=50),
    )
