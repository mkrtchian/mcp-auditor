import pytest
from rich.text import Text

import tests.unit.auditor.support.audit_displays as displays
import tests.unit.auditor.support.test_console_display_given as given
from mcp_auditor.domain.execution import ExecutionRegime
from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.rendering import describe_coverage_gap


def test_header_contains_the_server_command():
    display, buffer = displays.a_display()

    display.print_header("python server.py", ExecutionRegime.UNCONFINED)

    assert "python server.py" in buffer.getvalue()


@pytest.mark.parametrize(
    ("regime", "shown"),
    [
        (ExecutionRegime.CONFINED, "confined"),
        (ExecutionRegime.UNCONFINED, "unconfined"),
        (ExecutionRegime.DECLARED_CONTAINER, "declared container"),
    ],
)
def test_header_states_the_execution_regime(regime: ExecutionRegime, shown: str):
    display, buffer = displays.a_display()

    display.print_header("npx some-server", regime)

    assert f"execution: {shown}" in Text.from_ansi(buffer.getvalue()).plain


def test_summary_contains_score_and_tools():
    report = given.a_report_with_two_tools()
    display, buffer = displays.a_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "get_user" in output
    assert "list_items" in output
    assert "50%" in output  # 1 pass, 1 fail = 50% score
    assert "1,234" in output  # input tokens
    assert "567" in output  # output tokens


def test_dry_run_shows_arguments():
    payloads = given.dry_run_payloads()
    display, buffer = displays.a_display()

    display.print_dry_run_payloads("get_user", payloads)

    output = buffer.getvalue()
    assert "DROP TABLE" in output
    assert "Empty input" in output


def test_error_message_displayed():
    display, buffer = displays.a_display()

    display.print_error("connection failed")

    assert "connection failed" in buffer.getvalue()


def test_report_path_displayed():
    display, buffer = displays.a_display()

    display.print_report_path("report.json")

    assert "report.json" in buffer.getvalue()


def test_ci_mode_suppresses_header():
    display, buffer = displays.a_ci_display()

    display.print_header("python server.py", ExecutionRegime.UNCONFINED)

    assert buffer.getvalue() == ""


def test_ci_mode_prints_plain_summary():
    report = given.a_report_with_two_tools()
    display, buffer = displays.a_ci_display()

    display.print_summary(report)

    output = buffer.getvalue()
    assert "2 tools" in output
    assert "1 findings" in output


def test_ci_mode_shows_discovery():
    display, buffer = displays.a_ci_display()

    display.print_discovery(2, ["read_file", "write_file"])

    output = Text.from_ansi(buffer.getvalue()).plain
    assert "2 tools" in output
    assert "read_file" in output
    assert "write_file" in output


def test_discovery_columnar_for_many_tools():
    names = [f"tool_{i}" for i in range(8)]
    display, buffer = displays.a_plain_display()

    display.print_discovery(8, names)

    heading, *columns = buffer.getvalue().splitlines()
    assert heading == "Discovered 8 tools:"
    assert " ".join(columns).split() == names


def test_discovery_inline_for_few_tools():
    names = ["alpha", "beta", "gamma", "delta"]
    display, buffer = displays.a_plain_display()

    display.print_discovery(4, names)

    assert buffer.getvalue().splitlines() == ["Discovered 4 tools: alpha, beta, gamma, delta"]


def test_summary_warns_about_a_tool_with_a_coverage_gap():
    report = given.a_report_with_a_coverage_gap_on_get_user()
    display, buffer = displays.a_display()

    display.print_summary(report)

    warnings = _warnings(Text.from_ansi(buffer.getvalue()).plain)
    assert len(warnings) == 2
    assert "get_user" in warnings[0]
    assert "7 cases generated for 10 requested" in warnings[0]
    assert "injection" in warnings[0]
    assert "incomplete" in warnings[1]


def test_ci_mode_summary_warns_about_a_tool_with_a_coverage_gap():
    report = given.a_report_with_a_coverage_gap_on_get_user()
    display, buffer = displays.a_ci_display()

    display.print_summary(report)

    warnings = _warnings(buffer.getvalue())
    assert len(warnings) == 2
    assert "get_user" in warnings[0]
    assert "7 cases generated for 10 requested" in warnings[0]
    assert "incomplete" in warnings[1]


def test_summary_warns_about_the_calls_not_sent_to_a_tool_as_a_coverage_gap():
    report = given.a_report_with_calls_not_sent_on_get_user()
    display, buffer = displays.a_ci_display()

    display.print_summary(report)

    gap = report.tool_reports[0].coverage_gap
    assert gap is not None
    warnings = _warnings(buffer.getvalue())
    assert warnings[0] == f": get_user: coverage gap, {describe_coverage_gap(gap)}"
    assert "incomplete" in warnings[1]


def test_summary_warns_about_a_refusal_then_about_the_incomplete_audit():
    report = given.a_report_with_a_refused_chain_planning()
    display, buffer = displays.a_ci_display()

    display.print_summary(report)

    warnings = _warnings(buffer.getvalue())
    assert len(warnings) == 2
    assert "list_items" in warnings[0]
    assert "chain planning" in warnings[0]
    assert given.REFUSAL_MESSAGE in warnings[0]
    assert "incomplete" in warnings[1]


def test_missed_model_calls_are_warned_one_by_one_as_the_dry_run_does():
    display, buffer = displays.a_ci_display()
    refused = given.a_refused_chain_planning_on_list_items()

    display.print_missed_model_calls([refused, refused])

    warnings = _warnings(buffer.getvalue())
    assert len(warnings) == 2
    assert all(given.REFUSAL_MESSAGE in warning for warning in warnings)


def test_a_refusal_warning_prints_the_provider_message_verbatim():
    display, buffer = displays.a_ci_display()
    message = "Blocked [see policy] by [/moderation]"
    refused = MissedModelCall(
        tool_name="get_user",
        kind=ModelCallKind.JUDGMENT,
        cause=MissedCallCause.PROVIDER_REFUSAL,
        detail=message,
    )

    display.print_missed_model_calls([refused])

    assert message in _warnings(buffer.getvalue())[0]


@pytest.mark.parametrize(
    ("cause", "label"),
    [
        (MissedCallCause.PROVIDER_REFUSAL, "refused by the model provider"),
        (MissedCallCause.UNREADABLE_ANSWER, "unreadable answer from the model"),
        (MissedCallCause.PROVIDER_THROTTLED, "throttled past every retry"),
    ],
)
def test_a_missed_model_call_warning_names_its_cause(cause: MissedCallCause, label: str):
    display, buffer = displays.a_ci_display()
    missed = MissedModelCall(
        tool_name="get_user", kind=ModelCallKind.JUDGMENT, cause=cause, detail="x"
    )

    display.print_missed_model_calls([missed])

    assert f'get_user: {label}, judgment, "x"' in _warnings(buffer.getvalue())[0]


def test_summary_has_no_warning_without_a_coverage_gap():
    report = given.a_report_with_two_tools()
    display, buffer = displays.a_display()

    display.print_summary(report)

    assert "Warning" not in buffer.getvalue()


def test_summary_shows_the_throttled_requests():
    report = given.a_report_throttled(3)
    display, buffer = displays.a_display()

    display.print_summary(report)

    assert "Throttled: 3" in Text.from_ansi(buffer.getvalue()).plain


def test_ci_mode_summary_shows_the_throttled_requests():
    report = given.a_report_throttled(3)
    display, buffer = displays.a_ci_display()

    display.print_summary(report)

    assert "Throttled: 3" in buffer.getvalue()


def test_summary_omits_throttling_when_nothing_was_throttled():
    report = given.a_report_throttled(0)
    for display, buffer in (displays.a_display(), displays.a_ci_display()):
        display.print_summary(report)

        assert "Throttled" not in buffer.getvalue()


def _warnings(output: str) -> list[str]:
    return [" ".join(chunk.split()) for chunk in output.split("Warning")[1:]]
