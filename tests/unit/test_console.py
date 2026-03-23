import tests.unit.support.test_console_given as given
from mcp_auditor.console import format_failure_line, format_tool_summary
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    AuditReport,
    Severity,
    TokenUsage,
)

# --- Pure function tests ---


def test_format_failure_line_includes_owasp_id_for_mapped_category():
    result = given.a_fail_result(
        "get_user", AuditCategory.INJECTION, Severity.HIGH, "SQL injection via user_id"
    )

    line = format_failure_line(result)

    assert "MCP-05" in line


def test_format_failure_line_no_owasp_for_unmapped_category():
    result = given.a_fail_result(
        "get_user", AuditCategory.INPUT_VALIDATION, Severity.MEDIUM, "No length check"
    )

    line = format_failure_line(result)

    assert "MCP-" not in line


def test_format_failure_line_includes_category_severity_justification():
    result = given.a_fail_result(
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
        given.a_fail_result("get_user", AuditCategory.INJECTION, Severity.HIGH, "SQL injection"),
        given.a_fail_result(
            "get_user", AuditCategory.INPUT_VALIDATION, Severity.MEDIUM, "Negative ID"
        ),
    ]

    summary = format_tool_summary(fail_count=2, pass_count=3, failures=failures)

    assert "2" in summary
    assert "high" in summary.lower()
    assert "medium" in summary.lower()


def test_format_tool_summary_sorts_severity_descending():
    failures = [
        given.a_fail_result("get_user", AuditCategory.INPUT_VALIDATION, Severity.LOW, "Weak"),
        given.a_fail_result("get_user", AuditCategory.INJECTION, Severity.CRITICAL, "SQLi"),
        given.a_fail_result("get_user", AuditCategory.INJECTION, Severity.MEDIUM, "XSS"),
    ]

    summary = format_tool_summary(fail_count=3, pass_count=0, failures=failures)

    assert summary.index("critical") < summary.index("medium") < summary.index("low")


def test_format_tool_summary_zero_cases():
    summary = format_tool_summary(fail_count=0, pass_count=0, failures=[])

    # Should not crash, should produce some reasonable output
    assert isinstance(summary, str)


# --- AuditDisplay tests ---


def test_header_contains_target():
    display, buffer = given.a_display()

    display.print_header("python server.py")

    assert "python server.py" in buffer.getvalue()


def test_discovery_shows_count_and_names():
    display, buffer = given.a_display()

    display.print_discovery(3, ["a", "b", "c"])

    output = buffer.getvalue()
    assert "3" in output
    assert "a" in output
    assert "b" in output
    assert "c" in output


def test_summary_contains_score_and_tools():
    report = given.a_report_with_two_tools()
    display, buffer = given.a_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "get_user" in output
    assert "list_items" in output
    assert "50%" in output  # 1 pass, 1 fail = 50% score
    assert "1,234" in output  # input tokens
    assert "567" in output  # output tokens
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
    display, buffer = given.a_display()

    display.print_dry_run_payloads("get_user", payloads)

    output = buffer.getvalue()
    assert "DROP TABLE" in output
    assert "Empty input" in output


def test_error_message_displayed():
    display, buffer = given.a_display()

    display.print_error("connection failed")

    assert "connection failed" in buffer.getvalue()


def test_report_path_displayed():
    display, buffer = given.a_display()

    display.print_report_path("report.json")

    assert "report.json" in buffer.getvalue()


def test_ci_mode_suppresses_header():
    display, buffer = given.a_ci_display()

    display.print_header("python server.py")

    assert buffer.getvalue() == ""


def test_ci_mode_prints_plain_summary():
    report = given.a_report_with_two_tools()
    display, buffer = given.a_ci_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "2 tools" in output
    assert "1 findings" in output


def test_ci_mode_shows_discovery():
    display, buffer = given.a_ci_display()

    display.print_discovery(2, ["read_file", "write_file"])

    output = buffer.getvalue()
    assert "2" in output
    assert "read_file" in output


def test_ci_mode_progress_prints_tool_summary():
    display, buffer = given.a_ci_display()
    progress = display.create_tool_progress(1, 2, "get_user", 1)

    with progress:
        progress.advance(
            given.a_fail_result("get_user", AuditCategory.INJECTION, Severity.HIGH, "vuln")
        )

    output = buffer.getvalue()
    assert "get_user" in output
    assert "1 failed" in output
    assert "injection" in output


# --- Findings recap tests ---


def test_findings_recap_groups_by_severity():
    report = given.a_report_with_one_pass_plus_failures(
        {
            "get_user": [
                (Severity.MEDIUM, AuditCategory.INJECTION, "SQL injection possible"),
            ],
            "list_items": [
                (Severity.LOW, AuditCategory.INPUT_VALIDATION, "No length check"),
            ],
        }
    )
    display, buffer = given.a_display()

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
    report = given.a_report_with_one_pass_plus_failures({})
    display, buffer = given.a_display()

    display.print_findings_recap(report)

    assert buffer.getvalue() == ""


def test_findings_recap_ci_mode_plain_text():
    report = given.a_report_with_one_pass_plus_failures(
        {
            "get_user": [
                (Severity.HIGH, AuditCategory.INJECTION, "SQL injection found"),
            ],
        }
    )
    display, buffer = given.a_ci_display()

    display.print_findings_recap(report)

    output = buffer.getvalue()
    assert "Findings:" in output
    assert "HIGH" in output or "high" in output.lower()
    assert "get_user" in output
    assert "injection" in output.lower()
    assert "SQL injection found" in output


def test_summary_fail_column_shows_severity_breakdown():
    report = given.a_report_with_one_pass_plus_failures(
        {
            "get_user": [
                (Severity.MEDIUM, AuditCategory.INJECTION, "vuln1"),
                (Severity.LOW, AuditCategory.INPUT_VALIDATION, "vuln2"),
            ],
        }
    )
    display, buffer = given.a_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "medium" in output.lower()
    assert "low" in output.lower()


def test_summary_fail_column_zero_shows_no_breakdown():
    report = given.a_report_with_one_pass_plus_failures({"get_user": []})
    display, buffer = given.a_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "0" in output
    # Should not contain severity labels for a tool with 0 failures
    assert "medium" not in output.lower()
    assert "high" not in output.lower()
    assert "critical" not in output.lower()
    assert "low" not in output.lower()


def test_summary_score_line_high_score():
    report = given.a_report_with_n_results(pass_count=9, fail_count=1)
    display, buffer = given.a_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "90%" in output
    assert "\u2588" in output
    assert "\u2591" in output


def test_summary_score_line_low_score():
    report = given.a_report_with_n_results(pass_count=2, fail_count=8)
    display, buffer = given.a_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "20%" in output


def test_summary_score_line_zero_cases():
    report = AuditReport(
        target="python server.py",
        tool_reports=[],
        token_usage=TokenUsage(input_tokens=0, output_tokens=0),
    )
    display, buffer = given.a_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "0%" in output


def test_discovery_columnar_for_many_tools():
    names = [f"tool_{i}" for i in range(8)]
    display, buffer = given.a_display()

    display.print_discovery(8, names)

    output = buffer.getvalue()
    for name in names:
        assert name in output


def test_discovery_inline_for_few_tools():
    names = ["alpha", "beta", "gamma", "delta"]
    display, buffer = given.a_display()

    display.print_discovery(4, names)

    output = buffer.getvalue()
    for name in names:
        assert name in output
