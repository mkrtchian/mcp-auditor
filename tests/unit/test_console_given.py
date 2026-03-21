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


def a_report_with_failures(
    failures_per_tool: dict[str, list[tuple[Severity, AuditCategory, str]]],
) -> AuditReport:
    tool_reports: list[ToolReport] = []
    for tool_name, failures in failures_per_tool.items():
        cases = [
            TestCase(
                payload=AuditPayload(
                    tool_name=tool_name,
                    category=AuditCategory.INJECTION,
                    description="pass case",
                    arguments={},
                ),
                eval_result=EvalResult(
                    tool_name=tool_name,
                    category=AuditCategory.INJECTION,
                    payload={},
                    verdict=EvalVerdict.PASS,
                    justification="ok",
                    severity=Severity.LOW,
                ),
            )
        ]
        for severity, category, justification in failures:
            cases.append(
                TestCase(
                    payload=AuditPayload(
                        tool_name=tool_name,
                        category=category,
                        description="fail case",
                        arguments={},
                    ),
                    eval_result=EvalResult(
                        tool_name=tool_name,
                        category=category,
                        payload={},
                        verdict=EvalVerdict.FAIL,
                        justification=justification,
                        severity=severity,
                    ),
                )
            )
        tool_reports.append(
            ToolReport(
                tool=ToolDefinition(name=tool_name, description="", input_schema={}),
                cases=cases,
            )
        )
    return AuditReport(
        target="python server.py",
        tool_reports=tool_reports,
        token_usage=TokenUsage(input_tokens=100, output_tokens=50),
    )


def a_report_with_n_results(pass_count: int, fail_count: int) -> AuditReport:
    cases: list[TestCase] = []
    for _i in range(pass_count):
        cases.append(
            TestCase(
                payload=AuditPayload(
                    tool_name="tool_a",
                    category=AuditCategory.INJECTION,
                    description="test",
                    arguments={},
                ),
                eval_result=EvalResult(
                    tool_name="tool_a",
                    category=AuditCategory.INJECTION,
                    payload={},
                    verdict=EvalVerdict.PASS,
                    justification="ok",
                    severity=Severity.LOW,
                ),
            )
        )
    for _i in range(fail_count):
        cases.append(
            TestCase(
                payload=AuditPayload(
                    tool_name="tool_a",
                    category=AuditCategory.INJECTION,
                    description="test",
                    arguments={},
                ),
                eval_result=EvalResult(
                    tool_name="tool_a",
                    category=AuditCategory.INJECTION,
                    payload={},
                    verdict=EvalVerdict.FAIL,
                    justification="vuln",
                    severity=Severity.MEDIUM,
                ),
            )
        )
    return AuditReport(
        target="python server.py",
        tool_reports=[
            ToolReport(
                tool=ToolDefinition(name="tool_a", description="", input_schema={}),
                cases=cases,
            )
        ],
        token_usage=TokenUsage(input_tokens=100, output_tokens=50),
    )


def a_report_with_two_tools() -> AuditReport:
    return AuditReport(
        target="python server.py",
        tool_reports=[
            ToolReport(
                tool=ToolDefinition(name="get_user", description="", input_schema={}),
                cases=[
                    TestCase(
                        payload=AuditPayload(
                            tool_name="get_user",
                            category=AuditCategory.INJECTION,
                            description="test",
                            arguments={},
                        ),
                        eval_result=EvalResult(
                            tool_name="get_user",
                            category=AuditCategory.INJECTION,
                            payload={},
                            verdict=EvalVerdict.PASS,
                            justification="ok",
                            severity=Severity.LOW,
                        ),
                    )
                ],
            ),
            ToolReport(
                tool=ToolDefinition(name="list_items", description="", input_schema={}),
                cases=[
                    TestCase(
                        payload=AuditPayload(
                            tool_name="list_items",
                            category=AuditCategory.INPUT_VALIDATION,
                            description="test",
                            arguments={},
                        ),
                        eval_result=EvalResult(
                            tool_name="list_items",
                            category=AuditCategory.INPUT_VALIDATION,
                            payload={},
                            verdict=EvalVerdict.FAIL,
                            justification="bad",
                            severity=Severity.HIGH,
                        ),
                    )
                ],
            ),
        ],
        token_usage=TokenUsage(input_tokens=100, output_tokens=50),
    )
