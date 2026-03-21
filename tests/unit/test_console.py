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
    assert "100" in output  # input tokens or score percentage
    assert "50" in output  # output tokens or score percentage
    assert "\u2588" in output  # filled bar char
    assert "\u2591" in output  # empty bar char


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
        progress.advance(_a_fail_result("get_user", AuditCategory.INJECTION, Severity.HIGH, "vuln"))

    output = buffer.getvalue()
    assert "get_user" in output
    assert "1 failed" in output
    assert "injection" in output


# --- Findings recap tests ---


def test_findings_recap_groups_by_severity():
    report = _a_report_with_failures(
        {
            "get_user": [
                (Severity.MEDIUM, AuditCategory.INJECTION, "SQL injection possible"),
            ],
            "list_items": [
                (Severity.LOW, AuditCategory.INPUT_VALIDATION, "No length check"),
            ],
        }
    )
    display, buffer = _make_display()

    display.print_findings_recap(report)

    output = buffer.getvalue()
    assert "medium" in output.lower()
    assert "low" in output.lower()
    assert "get_user" in output
    assert "list_items" in output
    assert "injection" in output.lower()
    assert "input_validation" in output.lower()
    assert "SQL injection possible" in output
    assert "No length check" in output
    # MEDIUM should appear before LOW (higher severity first)
    medium_pos = output.lower().index("medium")
    low_pos = output.lower().index("low")
    assert medium_pos < low_pos


def test_findings_recap_empty_when_no_failures():
    report = _a_report_with_failures({})
    display, buffer = _make_display()

    display.print_findings_recap(report)

    assert buffer.getvalue() == ""


def test_findings_recap_ci_mode_plain_text():
    report = _a_report_with_failures(
        {
            "get_user": [
                (Severity.HIGH, AuditCategory.INJECTION, "SQL injection found"),
            ],
        }
    )
    display, buffer = _make_ci_display()

    display.print_findings_recap(report)

    output = buffer.getvalue()
    assert "Findings:" in output
    assert "HIGH" in output or "high" in output.lower()
    assert "get_user" in output
    assert "injection" in output.lower()
    assert "SQL injection found" in output


def test_summary_fail_column_shows_severity_breakdown():
    report = _a_report_with_failures(
        {
            "get_user": [
                (Severity.MEDIUM, AuditCategory.INJECTION, "vuln1"),
                (Severity.LOW, AuditCategory.INPUT_VALIDATION, "vuln2"),
            ],
        }
    )
    display, buffer = _make_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "medium" in output.lower()
    assert "low" in output.lower()


def test_summary_fail_column_zero_shows_no_breakdown():
    report = _a_report_with_failures({"get_user": []})
    display, buffer = _make_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "0" in output
    # Should not contain severity labels for a tool with 0 failures
    # The tool has no failures so no severity breakdown
    assert "medium" not in output.lower()
    assert "high" not in output.lower()
    assert "critical" not in output.lower()
    assert "low" not in output.lower()


def test_summary_score_line_high_score():
    report = _a_report_with_n_results(pass_count=9, fail_count=1)
    display, buffer = _make_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "90%" in output
    assert "\u2588" in output
    assert "\u2591" in output


def test_summary_score_line_low_score():
    report = _a_report_with_n_results(pass_count=2, fail_count=8)
    display, buffer = _make_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "20%" in output


def test_summary_score_line_zero_cases():
    report = AuditReport(
        target="python server.py",
        tool_reports=[],
        token_usage=TokenUsage(input_tokens=0, output_tokens=0),
    )
    display, buffer = _make_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "0%" in output


def test_discovery_columnar_for_many_tools():
    names = [f"tool_{i}" for i in range(8)]
    display, buffer = _make_display()

    display.print_discovery(8, names)

    output = buffer.getvalue()
    for name in names:
        assert name in output


def test_discovery_inline_for_few_tools():
    names = ["alpha", "beta", "gamma", "delta"]
    display, buffer = _make_display()

    display.print_discovery(4, names)

    output = buffer.getvalue()
    for name in names:
        assert name in output


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


def _a_report_with_failures(
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


def _a_report_with_n_results(pass_count: int, fail_count: int) -> AuditReport:
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
