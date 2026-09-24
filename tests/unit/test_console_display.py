from rich.text import Text

import tests.unit.support.test_console_given as given
from mcp_auditor.domain.models import AuditCategory, ExecutionRegime, Severity


def test_header_contains_target():
    display, buffer = given.a_display()

    display.print_header("python server.py", ExecutionRegime.UNCONFINED)

    assert "python server.py" in buffer.getvalue()


def test_header_states_the_execution_regime():
    display, buffer = given.a_display()

    display.print_header("npx some-server", ExecutionRegime.CONFINED)

    assert "confined" in buffer.getvalue()


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
    payloads = given.dry_run_payloads()
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

    display.print_header("python server.py", ExecutionRegime.UNCONFINED)

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

    progress.start()
    progress.advance(
        given.a_fail_result("get_user", AuditCategory.INJECTION, Severity.HIGH, "vuln")
    )
    progress.stop()

    output = buffer.getvalue()
    assert "get_user" in output
    assert "1 failed" in output
    assert "injection" in output


def test_summary_warns_about_a_tool_with_a_coverage_gap():
    report = given.a_report_with_a_coverage_gap_on_get_user()
    display, buffer = given.a_display()

    display.print_summary(report)

    output = Text.from_ansi(buffer.getvalue()).plain
    assert output.count("Warning") == 1
    warning = " ".join(output.split("Warning")[1].split())
    assert "get_user" in warning
    assert "7 of 10" in warning
    assert "injection" in warning


def test_ci_mode_summary_warns_about_a_tool_with_a_coverage_gap():
    report = given.a_report_with_a_coverage_gap_on_get_user()
    display, buffer = given.a_ci_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert output.count("Warning") == 1
    warning = " ".join(output.split("Warning")[1].split())
    assert "get_user" in warning
    assert "7 of 10" in warning


def test_summary_has_no_warning_without_a_coverage_gap():
    report = given.a_report_with_two_tools()
    display, buffer = given.a_display()

    display.print_summary(report)

    assert "Warning" not in buffer.getvalue()
