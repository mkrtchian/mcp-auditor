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


def test_header_contains_target():
    display, buffer = _make_display()

    display.print_header("python server.py")

    assert "python server.py" in buffer.getvalue()


def test_verdict_fail_shows_severity():
    display, buffer = _make_display()
    result = EvalResult(
        tool_name="get_user",
        category=AuditCategory.INJECTION,
        payload={},
        verdict=EvalVerdict.FAIL,
        justification="unsafe",
        severity=Severity.HIGH,
    )

    display.print_verdict(1, 5, result)

    output = buffer.getvalue()
    assert "FAIL" in output
    assert "high" in output


def test_verdict_pass_displayed():
    display, buffer = _make_display()
    result = EvalResult(
        tool_name="get_user",
        category=AuditCategory.INJECTION,
        payload={},
        verdict=EvalVerdict.PASS,
        justification="safe",
        severity=Severity.LOW,
    )

    display.print_verdict(1, 5, result)

    assert "PASS" in buffer.getvalue()


def test_discovery_shows_count_and_names():
    display, buffer = _make_display()

    display.print_discovery(3, ["a", "b", "c"])

    output = buffer.getvalue()
    assert "3" in output
    assert "a" in output
    assert "b" in output
    assert "c" in output


def test_summary_table_has_tool_names():
    report = _a_report_with_two_tools()
    display, buffer = _make_display()

    display.print_summary_table(report)

    output = buffer.getvalue()
    assert "get_user" in output
    assert "list_items" in output


def test_dry_run_shows_arguments():
    payloads = [
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
    display, buffer = _make_display()

    display.print_dry_run_payloads("get_user", payloads)

    output = buffer.getvalue()
    assert "DROP TABLE" in output
    assert "Empty input" in output


def _make_display() -> tuple[AuditDisplay, StringIO]:
    buffer = StringIO()
    console = Console(file=buffer, force_terminal=True)
    return AuditDisplay(console=console), buffer


def _a_report_with_two_tools() -> AuditReport:
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
