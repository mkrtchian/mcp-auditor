import tests.unit.support.test_console_given as given
from mcp_auditor.console import format_failure_line, format_tool_summary
from mcp_auditor.domain.models import AuditCategory, Severity


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
