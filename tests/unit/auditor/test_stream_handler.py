import pytest
from rich.text import Text

import tests.unit.auditor.support.audit_displays as displays
from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import AuditCategory, AuditPayload, ProviderUsage, TestCase
from mcp_auditor.domain.relaunch_rendering import UNSENT_CAUSE_LABELS, describe_relaunch
from mcp_auditor.domain.server_liveness import Relaunch, RelaunchCause, UnsentCause
from mcp_auditor.stream_handler import AuditProgressReporter

TOOL_AUDIT_NAMESPACE = ("audit_tool:1",)
CHAIN_AUDIT_NAMESPACE = ("chain_audit_tool:1",)
BLOCKED_REASON = "destructive filesystem command: rm -rf"


def test_a_blocked_case_is_reported_while_the_audit_runs():
    display, buffer = displays.a_ci_display()
    reporter = AuditProgressReporter(display)
    reporter.on_stream_event(_a_generation_event())

    reporter.on_stream_event(
        (
            TOOL_AUDIT_NAMESPACE,
            {"execute_tool": {"processed_cases": [_a_case(BLOCKED_REASON)], "current_case": None}},
        )
    )

    assert BLOCKED_REASON in buffer.getvalue()


def test_a_normal_execution_reports_nothing():
    display, buffer = displays.a_ci_display()
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
    display, buffer = displays.a_display()
    reporter = AuditProgressReporter(display)
    reporter.on_stream_event(_a_generation_event())

    for _ in range(2):
        reporter.on_stream_event(_an_unjudged_event(MissedCallCause.PROVIDER_REFUSAL))
    reporter.on_stream_event(((), {"build_tool_report": {}}))

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
    reporter.on_stream_event(_a_generation_event())

    reporter.on_stream_event(_an_unjudged_event(cause))

    assert line in buffer.getvalue()


def test_a_throttled_provider_is_warned_about_once():
    display, buffer = displays.a_ci_display()
    reporter = AuditProgressReporter(display)

    reporter.on_stream_event(_a_usage_event((), ProviderUsage(throttled_requests=1)))
    reporter.on_stream_event(
        _a_usage_event(TOOL_AUDIT_NAMESPACE, ProviderUsage(throttled_requests=2))
    )

    assert buffer.getvalue().count("HTTP 429") == 1


def test_an_unthrottled_provider_is_not_warned_about():
    display, buffer = displays.a_ci_display()
    reporter = AuditProgressReporter(display)

    reporter.on_stream_event(_a_usage_event((), ProviderUsage(input_tokens=10)))
    reporter.on_stream_event(_a_usage_event(TOOL_AUDIT_NAMESPACE, ProviderUsage()))

    assert buffer.getvalue() == ""


def test_each_relaunch_is_reported_once_as_a_case_or_a_chain_step_records_it():
    display, buffer = displays.a_ci_display()
    reporter = AuditProgressReporter(display)
    lost = _a_relaunch(RelaunchCause.LOST_CONNECTION, succeeded=True)
    stuck = _a_relaunch(RelaunchCause.STUCK, succeeded=False)

    reporter.on_stream_event((TOOL_AUDIT_NAMESPACE, {"execute_tool": {"relaunches": [lost]}}))
    reporter.on_stream_event((CHAIN_AUDIT_NAMESPACE, {"execute_step": {"relaunches": [stuck]}}))
    reporter.on_stream_event(((), {"audit_tool": {"relaunches": [lost]}}))

    warnings = [" ".join(chunk.split()) for chunk in buffer.getvalue().split("Warning: ")[1:]]
    assert warnings == [
        f"run_command: {describe_relaunch(lost)}",
        f"run_command: {describe_relaunch(stuck)}",
    ]


def test_cases_not_sent_advance_the_progress_bar_to_its_end():
    display, buffer = displays.a_display()
    reporter = AuditProgressReporter(display)
    reporter.on_stream_event(_a_generation_event())

    for _ in range(2):
        reporter.on_stream_event(_a_case_not_sent_event(UnsentCause.TOOL_TIMING_OUT))
    reporter.on_stream_event(((), {"build_tool_report": {}}))

    output = Text.from_ansi(buffer.getvalue()).plain
    assert "2/2" in output
    cause = UNSENT_CAUSE_LABELS[UnsentCause.TOOL_TIMING_OUT]
    assert output.count(f"calls not sent from here on: {cause}") == 1


def _a_relaunch(cause: RelaunchCause, succeeded: bool) -> Relaunch:
    return Relaunch(
        tool_name="run_command", arguments={"command": "ls"}, cause=cause, succeeded=succeeded
    )


def _a_case_not_sent_event(cause: UnsentCause) -> tuple[tuple[str, ...], dict[str, object]]:
    update: dict[str, object] = {"pending_cases": [], "unsent_cases": 1, "unsent_cause": cause}
    return (TOOL_AUDIT_NAMESPACE, {"execute_tool": update})


def _a_usage_event(
    namespace: tuple[str, ...], usage: ProviderUsage
) -> tuple[tuple[str, ...], dict[str, object]]:
    return (namespace, {"judge_response": {"provider_usage": [usage]}})


def _an_unjudged_event(cause: MissedCallCause) -> tuple[tuple[str, ...], dict[str, object]]:
    missed = MissedModelCall(
        tool_name="run_command", kind=ModelCallKind.JUDGMENT, cause=cause, detail="x"
    )
    return (
        TOOL_AUDIT_NAMESPACE,
        {"judge_response": {"processed_cases": [_a_case()], "missed_model_calls": [missed]}},
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
