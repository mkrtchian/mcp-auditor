import pytest
from rich.text import Text

import tests.unit.auditor.support.audit_displays as displays
import tests.unit.auditor.support.test_stream_handler_given as given
from mcp_auditor.domain.model_calls import MissedCallCause
from mcp_auditor.domain.models import ProviderUsage
from mcp_auditor.domain.relaunch_rendering import UNSENT_CAUSE_LABELS, describe_relaunch
from mcp_auditor.domain.server_liveness import RelaunchCause, UnsentCause
from mcp_auditor.stream_handler import AuditProgressReporter


def test_a_blocked_case_is_reported_while_the_audit_runs():
    display, buffer = displays.a_ci_display()
    reporter = AuditProgressReporter(display)
    reporter.on_stream_event(given.a_generation_event())

    reporter.on_stream_event(given.an_execution_event_of_a_blocked_case(given.BLOCKED_REASON))

    assert given.BLOCKED_REASON in buffer.getvalue()


def test_a_normal_execution_reports_nothing():
    display, buffer = displays.a_ci_display()
    reporter = AuditProgressReporter(display)
    reporter.on_stream_event(given.a_generation_event())

    reporter.on_stream_event(given.an_execution_event_of_a_sent_case())

    assert buffer.getvalue() == ""


def test_an_unjudged_case_advances_the_progress_bar():
    display, buffer = displays.a_display()
    reporter = AuditProgressReporter(display)
    reporter.on_stream_event(given.a_generation_event())

    for _ in range(2):
        reporter.on_stream_event(given.an_unjudged_event(MissedCallCause.PROVIDER_REFUSAL))
    reporter.on_stream_event(given.a_tool_report_event())

    output = Text.from_ansi(buffer.getvalue()).plain
    assert "2/2" in output
    assert "not judged" in output


@pytest.mark.parametrize(
    ("cause", "line"),
    [
        (MissedCallCause.PROVIDER_REFUSAL, "? not judged, the model provider refused the judgment"),
        (MissedCallCause.UNREADABLE_ANSWER, "? not judged, the model's answer was unreadable"),
        (
            MissedCallCause.PROVIDER_THROTTLED,
            "? not judged, the model provider throttled the judgment past every retry",
        ),
        (
            MissedCallCause.PROMPT_TOO_LONG,
            "? not judged, the prompt was longer than the model's context window",
        ),
    ],
)
def test_an_unjudged_case_names_the_cause_of_its_missed_judgment(cause: MissedCallCause, line: str):
    display, buffer = displays.a_ci_display()
    reporter = AuditProgressReporter(display)
    reporter.on_stream_event(given.a_generation_event())

    reporter.on_stream_event(given.an_unjudged_event(cause))

    assert line in buffer.getvalue()


def test_a_throttled_provider_is_warned_about_once():
    display, buffer = displays.a_ci_display()
    reporter = AuditProgressReporter(display)

    reporter.on_stream_event(given.a_usage_event((), ProviderUsage(throttled_requests=1)))
    reporter.on_stream_event(
        given.a_usage_event(given.TOOL_AUDIT_NAMESPACE, ProviderUsage(throttled_requests=2))
    )

    assert buffer.getvalue().count("HTTP 429") == 1


def test_an_unthrottled_provider_is_not_warned_about():
    display, buffer = displays.a_ci_display()
    reporter = AuditProgressReporter(display)

    reporter.on_stream_event(given.a_usage_event((), ProviderUsage(input_tokens=10)))
    reporter.on_stream_event(given.a_usage_event(given.TOOL_AUDIT_NAMESPACE, ProviderUsage()))

    assert buffer.getvalue() == ""


def test_each_relaunch_is_reported_once_as_a_case_or_a_chain_step_records_it():
    display, buffer = displays.a_ci_display()
    reporter = AuditProgressReporter(display)
    lost = given.a_relaunch(RelaunchCause.LOST_CONNECTION, succeeded=True)
    stuck = given.a_relaunch(RelaunchCause.STUCK, succeeded=False)

    reporter.on_stream_event((given.TOOL_AUDIT_NAMESPACE, {"execute_tool": {"relaunches": [lost]}}))
    reporter.on_stream_event(
        (given.CHAIN_AUDIT_NAMESPACE, {"execute_step": {"relaunches": [stuck]}})
    )
    reporter.on_stream_event(((), {"audit_tool": {"relaunches": [lost]}}))

    warnings = [" ".join(chunk.split()) for chunk in buffer.getvalue().split("Warning: ")[1:]]
    assert warnings == [
        f"run_command: {describe_relaunch(lost)}",
        f"run_command: {describe_relaunch(stuck)}",
    ]


def test_cases_not_sent_advance_the_progress_bar_to_its_end():
    display, buffer = displays.a_display()
    reporter = AuditProgressReporter(display)
    reporter.on_stream_event(given.a_generation_event())

    for _ in range(2):
        reporter.on_stream_event(given.a_case_not_sent_event(UnsentCause.TOOL_TIMING_OUT))
    reporter.on_stream_event(given.a_tool_report_event())

    output = Text.from_ansi(buffer.getvalue()).plain
    assert "2/2" in output
    cause = UNSENT_CAUSE_LABELS[UnsentCause.TOOL_TIMING_OUT]
    assert output.count(f"calls not sent from here on: {cause}") == 1


async def test_the_progress_follows_a_real_audit_stream():
    display, buffer = displays.a_ci_display()
    reporter = AuditProgressReporter(display)

    for event in await given.events_of_a_real_audit_with_one_chain():
        reporter.on_stream_event(event)

    output = buffer.getvalue()
    assert "[1/1] get_user: \u2717 1 failed (1 medium)" in output
    assert "Planning 1 attack chain(s)" in output
    assert "Chain judged: fail" in output
