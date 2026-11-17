from rich.text import Text

import tests.unit.auditor.support.test_console_given as given
from mcp_auditor.domain.models import AuditCategory, Severity
from mcp_auditor.domain.server_liveness import UnsentCause
from mcp_auditor.progress import format_failure_line, format_tool_summary


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
    summary = format_tool_summary(fail_count=0, failures=[])

    assert "passed" in summary.lower()


def test_format_tool_summary_with_failures():
    failures = [
        given.a_fail_result("get_user", AuditCategory.INJECTION, Severity.HIGH, "SQL injection"),
        given.a_fail_result(
            "get_user", AuditCategory.INPUT_VALIDATION, Severity.MEDIUM, "Negative ID"
        ),
    ]

    summary = format_tool_summary(fail_count=2, failures=failures)

    assert "2" in summary
    assert "high" in summary.lower()
    assert "medium" in summary.lower()


def test_format_tool_summary_sorts_severity_descending():
    failures = [
        given.a_fail_result("get_user", AuditCategory.INPUT_VALIDATION, Severity.LOW, "Weak"),
        given.a_fail_result("get_user", AuditCategory.INJECTION, Severity.CRITICAL, "SQLi"),
        given.a_fail_result("get_user", AuditCategory.INJECTION, Severity.MEDIUM, "XSS"),
    ]

    summary = format_tool_summary(fail_count=3, failures=failures)

    assert summary.index("critical") < summary.index("medium") < summary.index("low")


def test_tool_progress_advance_blocked_names_the_reason_without_counting_a_failure():
    display, buffer = given.a_display()
    progress = display.create_tool_progress(1, 1, "run_command", 2)
    progress.start()

    progress.advance_blocked("destructive filesystem command: rm -rf")
    progress.stop()

    output = buffer.getvalue()
    assert "destructive filesystem command: rm -rf" in output
    assert "all passed" in output


def test_ci_progress_advance_blocked_names_the_reason():
    display, buffer = given.a_ci_display()
    progress = display.create_tool_progress(1, 1, "run_command", 2)
    progress.start()

    progress.advance_blocked("destructive SQL statement: drop table")

    assert "destructive SQL statement: drop table" in buffer.getvalue()


def test_a_blocked_line_names_the_guard_and_leaves_not_sent_to_calls_withheld():
    display, buffer = given.a_ci_display()
    progress = display.create_tool_progress(1, 1, "run_command", 1)

    progress.advance_blocked("destructive SQL statement: drop table")

    assert "blocked by the guard: destructive SQL statement: drop table" in buffer.getvalue()
    assert "not sent" not in buffer.getvalue()


def test_tool_progress_reaches_its_end_on_cases_not_sent_and_names_their_cause_once():
    display, buffer = given.a_display()
    progress = display.create_tool_progress(1, 1, "run_command", 3)
    progress.start()

    progress.advance(
        given.a_fail_result("run_command", AuditCategory.INJECTION, Severity.HIGH, "x")
    )
    for _ in range(2):
        progress.advance_unsent(UnsentCause.RELAUNCHES_IN_A_ROW)
    progress.stop()

    output = Text.from_ansi(buffer.getvalue()).plain
    assert "3/3" in output
    assert output.count("calls not sent from here on: the tool's calls led to 2 relaunches") == 1


def test_ci_progress_names_the_cause_of_cases_not_sent_once():
    display, buffer = given.a_ci_display()
    progress = display.create_tool_progress(1, 1, "run_command", 2)

    for _ in range(2):
        progress.advance_unsent(UnsentCause.SERVER_DOWN)

    assert buffer.getvalue().count("not sent from here on: the server was taken as down") == 1
