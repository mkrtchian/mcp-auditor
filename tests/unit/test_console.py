from io import StringIO

from rich.console import Console

from mcp_auditor.console import AuditDisplay, format_failure_line, format_tool_summary
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

# --- Pure function tests ---


def test_format_failure_line_includes_category_severity_justification():
    result = _a_fail_result(
        "get_user", AuditCategory.INJECTION, Severity.HIGH, "SQL injection via user_id"
    )

    line = format_failure_line(result)

    assert "injection" in line
    assert "high" in line
    assert "SQL injection via user_id" in line


def test_format_tool_summary_all_passed():
    summary = format_tool_summary(fail_count=0, pass_count=5, failures=[])

    assert "passed" in summary.lower()


def test_format_tool_summary_with_failures():
    failures = [
        _a_fail_result("get_user", AuditCategory.INJECTION, Severity.HIGH, "SQL injection"),
        _a_fail_result("get_user", AuditCategory.INPUT_VALIDATION, Severity.MEDIUM, "Negative ID"),
    ]

    summary = format_tool_summary(fail_count=2, pass_count=3, failures=failures)

    assert "2" in summary
    assert "high" in summary.lower()
    assert "medium" in summary.lower()


def test_format_tool_summary_zero_cases():
    summary = format_tool_summary(fail_count=0, pass_count=0, failures=[])

    # Should not crash, should produce some reasonable output
    assert isinstance(summary, str)


# --- AuditDisplay tests ---


def test_header_contains_target():
    display, buffer = _make_display()

    display.print_header("python server.py")

    assert "python server.py" in buffer.getvalue()


def test_discovery_shows_count_and_names():
    display, buffer = _make_display()

    display.print_discovery(3, ["a", "b", "c"])

    output = buffer.getvalue()
    assert "3" in output
    assert "a" in output
    assert "b" in output
    assert "c" in output


def test_summary_contains_score_and_tools():
    report = _a_report_with_two_tools()
    display, buffer = _make_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "get_user" in output
    assert "list_items" in output
    assert "100" in output  # input tokens
    assert "50" in output  # output tokens


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


def test_error_message_displayed():
    display, buffer = _make_display()

    display.print_error("connection failed")

    assert "connection failed" in buffer.getvalue()


def test_report_path_displayed():
    display, buffer = _make_display()

    display.print_report_path("report.json")

    assert "report.json" in buffer.getvalue()


def test_ci_mode_suppresses_header():
    display, buffer = _make_ci_display()

    display.print_header("python server.py")

    assert buffer.getvalue() == ""


def test_ci_mode_prints_plain_summary():
    report = _a_report_with_two_tools()
    display, buffer = _make_ci_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "2 tools" in output
    assert "1 findings" in output


def test_ci_mode_shows_discovery():
    display, buffer = _make_ci_display()

    display.print_discovery(2, ["read_file", "write_file"])

    output = buffer.getvalue()
    assert "2" in output
    assert "read_file" in output


def test_ci_mode_progress_prints_tool_summary():
    display, buffer = _make_ci_display()
    progress = display.create_tool_progress(1, 2, "get_user", 1)

    with progress:
        progress.advance(
            _a_fail_result("get_user", AuditCategory.INJECTION, Severity.HIGH, "vuln")
        )

    output = buffer.getvalue()
    assert "get_user" in output
    assert "1 failed" in output
    assert "injection" in output


# --- Helpers ---


def _make_display() -> tuple[AuditDisplay, StringIO]:
    buffer = StringIO()
    console = Console(file=buffer, force_terminal=True)
    return AuditDisplay(console=console), buffer


def _make_ci_display() -> tuple[AuditDisplay, StringIO]:
    buffer = StringIO()
    console = Console(file=buffer, force_terminal=False, no_color=True)
    return AuditDisplay(console=console, ci_mode=True), buffer


def _a_fail_result(
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
