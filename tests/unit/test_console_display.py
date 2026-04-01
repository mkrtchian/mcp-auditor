import tests.unit.support.test_console_given as given
from mcp_auditor.domain.models import AuditCategory, AuditPayload, Severity


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

    progress.start()
    progress.advance(
        given.a_fail_result("get_user", AuditCategory.INJECTION, Severity.HIGH, "vuln")
    )
    progress.stop()

    output = buffer.getvalue()
    assert "get_user" in output
    assert "1 failed" in output
    assert "injection" in output
