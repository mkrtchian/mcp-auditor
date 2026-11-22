from rich.text import Text

import tests.unit.auditor.support.audit_displays as displays
import tests.unit.auditor.support.report_builders as reports
from mcp_auditor.domain.models import AuditCategory, Severity
from mcp_auditor.domain.relaunch_rendering import UNSENT_CAUSE_LABELS
from mcp_auditor.domain.server_liveness import UnsentCause
from mcp_auditor.progress import format_failure_line, format_tool_summary


def test_format_failure_line_includes_owasp_id_for_mapped_category():
    result = reports.a_fail_result(
        "get_user", AuditCategory.INJECTION, Severity.HIGH, "SQL injection via user_id"
    )

    line = format_failure_line(result)

    assert "MCP-05" in line


def test_format_failure_line_no_owasp_for_unmapped_category():
    result = reports.a_fail_result(
        "get_user", AuditCategory.INPUT_VALIDATION, Severity.MEDIUM, "No length check"
    )

    line = format_failure_line(result)

    assert "MCP-" not in line


def test_format_failure_line_includes_category_severity_justification():
    result = reports.a_fail_result(
        "get_user", AuditCategory.INJECTION, Severity.HIGH, "SQL injection via user_id"
    )

    line = format_failure_line(result)

    assert "injection" in line
    assert "high" in line
    assert "SQL injection via user_id" in line


def test_format_tool_summary_all_passed():
    summary = format_tool_summary(failures=[])

    assert "passed" in summary.lower()


def test_format_tool_summary_with_failures():
    failures = [
        reports.a_fail_result("get_user", AuditCategory.INJECTION, Severity.HIGH, "SQL injection"),
        reports.a_fail_result(
            "get_user", AuditCategory.INPUT_VALIDATION, Severity.MEDIUM, "Negative ID"
        ),
    ]

    summary = format_tool_summary(failures)

    assert "2" in summary
    assert "high" in summary.lower()
    assert "medium" in summary.lower()


def test_format_tool_summary_sorts_severity_descending():
    failures = [
        reports.a_fail_result("get_user", AuditCategory.INPUT_VALIDATION, Severity.LOW, "Weak"),
        reports.a_fail_result("get_user", AuditCategory.INJECTION, Severity.CRITICAL, "SQLi"),
        reports.a_fail_result("get_user", AuditCategory.INJECTION, Severity.MEDIUM, "XSS"),
    ]

    summary = format_tool_summary(failures)

    assert summary.index("critical") < summary.index("medium") < summary.index("low")


def test_tool_progress_advance_blocked_names_the_reason_without_counting_a_failure():
    display, buffer = displays.a_display()
    progress = display.create_tool_progress(1, 1, "run_command", 2)
    progress.start()

    progress.advance_blocked("destructive filesystem command: rm -rf")
    progress.stop()

    output = buffer.getvalue()
    assert "destructive filesystem command: rm -rf" in output
    assert "all passed" in output


def test_ci_progress_advance_blocked_names_the_reason():
    display, buffer = displays.a_ci_display()
    progress = display.create_tool_progress(1, 1, "run_command", 2)
    progress.start()

    progress.advance_blocked("destructive SQL statement: drop table")

    assert "destructive SQL statement: drop table" in buffer.getvalue()


def test_ci_mode_progress_prints_tool_summary():
    display, buffer = displays.a_ci_display()
    progress = display.create_tool_progress(1, 2, "get_user", 1)

    progress.start()
    progress.advance(
        reports.a_fail_result("get_user", AuditCategory.INJECTION, Severity.HIGH, "vuln")
    )
    progress.stop()

    output = buffer.getvalue()
    assert "get_user" in output
    assert "1 failed" in output
    assert "injection" in output


def test_a_blocked_line_names_the_guard_and_leaves_not_sent_to_calls_withheld():
    display, buffer = displays.a_ci_display()
    progress = display.create_tool_progress(1, 1, "run_command", 1)

    progress.advance_blocked("destructive SQL statement: drop table")

    assert "blocked by the guard: destructive SQL statement: drop table" in buffer.getvalue()
    assert "not sent" not in buffer.getvalue()


def test_tool_progress_reaches_its_end_on_cases_not_sent_and_names_their_cause_once():
    display, buffer = displays.a_display()
    progress = display.create_tool_progress(1, 1, "run_command", 3)
    progress.start()

    progress.advance(
        reports.a_fail_result("run_command", AuditCategory.INJECTION, Severity.HIGH, "x")
    )
    for _ in range(2):
        progress.advance_unsent(UnsentCause.RELAUNCHES_IN_A_ROW)
    progress.stop()

    output = Text.from_ansi(buffer.getvalue()).plain
    assert "3/3" in output
    cause = UNSENT_CAUSE_LABELS[UnsentCause.RELAUNCHES_IN_A_ROW]
    assert output.count(f"calls not sent from here on: {cause}") == 1


def test_ci_progress_names_the_cause_of_cases_not_sent_once():
    display, buffer = displays.a_ci_display()
    progress = display.create_tool_progress(1, 1, "run_command", 2)

    for _ in range(2):
        progress.advance_unsent(UnsentCause.SERVER_DOWN)

    cause = UNSENT_CAUSE_LABELS[UnsentCause.SERVER_DOWN]
    assert buffer.getvalue().count(f"not sent from here on: {cause}") == 1
