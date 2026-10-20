import tests.unit.support.test_console_findings_then as then
import tests.unit.support.test_console_given as given
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditReport,
    ProviderUsage,
    Severity,
)


def test_findings_recap_groups_by_severity():
    report = given.a_report_with_one_pass_plus_failures(
        {
            "list_items": [
                (Severity.LOW, AuditCategory.INPUT_VALIDATION, "No length check"),
            ],
            "get_user": [
                (Severity.MEDIUM, AuditCategory.INJECTION, "SQL injection possible"),
            ],
        }
    )
    display, buffer = given.a_plain_display()

    display.print_findings_recap(report)

    then.findings_recap_reads(
        buffer.getvalue(),
        [
            "MEDIUM",
            "get_user > injection / MCP-05 — SQL injection possible",
            "LOW",
            "list_items > input_validation — No length check",
        ],
    )


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
    display, buffer = given.a_plain_display()

    display.print_summary(report)

    output = buffer.getvalue()
    then.summary_row_reads(output, "get_user", ["get_user", "1", "1", "0"])
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
        provider_usage=ProviderUsage(input_tokens=0, output_tokens=0),
    )
    display, buffer = given.a_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "0%" in output


def test_discovery_columnar_for_many_tools():
    names = [f"tool_{i}" for i in range(8)]
    display, buffer = given.a_plain_display()

    display.print_discovery(8, names)

    heading, *columns = buffer.getvalue().splitlines()
    assert heading == "Discovered 8 tools:"
    assert " ".join(columns).split() == names


def test_discovery_inline_for_few_tools():
    names = ["alpha", "beta", "gamma", "delta"]
    display, buffer = given.a_plain_display()

    display.print_discovery(4, names)

    assert buffer.getvalue().splitlines() == ["Discovered 4 tools: alpha, beta, gamma, delta"]
