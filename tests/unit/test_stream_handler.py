import pytest
from rich.text import Text

import tests.unit.support.test_console_given as given
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    AuditStep,
    MissCause,
    MissedStep,
    ProviderUsage,
    TestCase,
)
from mcp_auditor.stream_handler import AuditProgressReporter

TOOL_AUDIT_NAMESPACE = ("audit_tool:1",)
BLOCKED_REASON = "destructive filesystem command: rm -rf"


def test_a_blocked_case_is_reported_while_the_audit_runs():
    display, buffer = given.a_ci_display()
    reporter = AuditProgressReporter(display)
    reporter.on_stream_event(_a_generation_event())

    reporter.on_stream_event(
        (
            TOOL_AUDIT_NAMESPACE,
            {"execute_tool": {"judged_cases": [_a_case(BLOCKED_REASON)], "current_case": None}},
        )
    )

    assert BLOCKED_REASON in buffer.getvalue()


def test_a_normal_execution_reports_nothing():
    display, buffer = given.a_ci_display()
    reporter = AuditProgressReporter(display)
    reporter.on_stream_event(_a_generation_event())

    reporter.on_stream_event(
        (
            TOOL_AUDIT_NAMESPACE,
            {"execute_tool": {"current_case": _a_case(), "pending_cases": []}},
        )
    )

    assert buffer.getvalue() == ""


def test_an_unjudged_case_advances_the_progress_bar():
    display, buffer = given.a_display()
    reporter = AuditProgressReporter(display)
    reporter.on_stream_event(_a_generation_event())

    for _ in range(2):
        reporter.on_stream_event(_an_unjudged_event(MissCause.PROVIDER_REFUSAL))
    reporter.on_stream_event(((), {"build_tool_report": {}}))

    output = Text.from_ansi(buffer.getvalue()).plain
    assert "2/2" in output
    assert "not judged" in output


@pytest.mark.parametrize(
    ("cause", "line"),
    [
        (MissCause.PROVIDER_REFUSAL, "? not judged, the model provider refused the judgment"),
        (MissCause.UNREADABLE_ANSWER, "? not judged, the model's answer was unreadable"),
        (
            MissCause.PROVIDER_THROTTLED,
            "? not judged, the model provider throttled the judgment past every retry",
        ),
    ],
)
def test_an_unjudged_case_names_the_cause_of_its_missed_judgment(cause: MissCause, line: str):
    display, buffer = given.a_ci_display()
    reporter = AuditProgressReporter(display)
    reporter.on_stream_event(_a_generation_event())

    reporter.on_stream_event(_an_unjudged_event(cause))

    assert line in buffer.getvalue()


def test_a_throttled_provider_is_warned_about_once():
    display, buffer = given.a_ci_display()
    reporter = AuditProgressReporter(display)

    reporter.on_stream_event(_a_usage_event((), ProviderUsage(throttled_requests=1)))
    reporter.on_stream_event(
        _a_usage_event(TOOL_AUDIT_NAMESPACE, ProviderUsage(throttled_requests=2))
    )

    assert buffer.getvalue().count("HTTP 429") == 1


def test_an_unthrottled_provider_is_not_warned_about():
    display, buffer = given.a_ci_display()
    reporter = AuditProgressReporter(display)

    reporter.on_stream_event(_a_usage_event((), ProviderUsage(input_tokens=10)))
    reporter.on_stream_event(_a_usage_event(TOOL_AUDIT_NAMESPACE, ProviderUsage()))

    assert buffer.getvalue() == ""


def _a_usage_event(
    namespace: tuple[str, ...], usage: ProviderUsage
) -> tuple[tuple[str, ...], dict[str, object]]:
    return (namespace, {"judge_response": {"provider_usage": [usage]}})


def _an_unjudged_event(cause: MissCause) -> tuple[tuple[str, ...], dict[str, object]]:
    missed = MissedStep(tool_name="run_command", step=AuditStep.JUDGMENT, cause=cause, detail="x")
    return (
        TOOL_AUDIT_NAMESPACE,
        {"judge_response": {"judged_cases": [_a_case()], "missed_steps": [missed]}},
    )


def _a_generation_event() -> tuple[tuple[str, ...], dict[str, object]]:
    return (
        TOOL_AUDIT_NAMESPACE,
        {"generate_test_cases": {"pending_cases": [_a_case(), _a_case()]}},
    )


def _a_case(blocked_reason: str | None = None) -> TestCase:
    return TestCase(
        payload=AuditPayload(
            category=AuditCategory.INJECTION,
            description="wipe the filesystem",
            arguments={"command": "rm -rf /"},
        ),
        blocked_reason=blocked_reason,
    )
