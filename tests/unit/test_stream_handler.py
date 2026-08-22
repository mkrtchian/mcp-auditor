import tests.unit.support.test_console_given as given
from mcp_auditor.domain.models import AuditCategory, AuditPayload, TestCase
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
