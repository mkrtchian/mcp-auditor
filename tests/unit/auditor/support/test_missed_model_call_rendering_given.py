from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import AuditCategory, AuditPayload, AuditReport, TestCase
from tests.unit.auditor.support.report_builders import (
    REFUSAL_MESSAGE,
    a_chain,
    a_report,
    a_run_command_tool_report,
    a_two_tool_report,
)

UNREADABLE_DETAIL = (
    "no answer matched the expected format after 3 attempts (1 cut at the output limit)"
)


def a_report_with_missed_judgments_on_get_user(refused: int, unreadable: int) -> AuditReport:
    report = a_two_tool_report()
    causes = [MissedCallCause.PROVIDER_REFUSAL] * refused + [
        MissedCallCause.UNREADABLE_ANSWER
    ] * unreadable
    report.missed_model_calls = [
        MissedModelCall(
            tool_name="get_user",
            kind=ModelCallKind.JUDGMENT,
            cause=cause,
            detail=REFUSAL_MESSAGE
            if cause == MissedCallCause.PROVIDER_REFUSAL
            else UNREADABLE_DETAIL,
        )
        for cause in causes
    ]
    return report


THROTTLE_MESSAGE = "429 RESOURCE_EXHAUSTED"


PROMPT_TOO_LONG_MESSAGE = "prompt of 1048577 tokens over the limit"


def a_report_with_one_missed_judgment_on_get_user(
    cause: MissedCallCause, detail: str
) -> AuditReport:
    report = a_two_tool_report()
    report.missed_model_calls = [
        MissedModelCall(
            tool_name="get_user", kind=ModelCallKind.JUDGMENT, cause=cause, detail=detail
        )
    ]
    return report


def a_report_with_an_unjudged_case() -> AuditReport:
    unjudged = TestCase(
        payload=AuditPayload(
            category=AuditCategory.INJECTION,
            description="shell metacharacters",
            arguments={"command": "ls; cat /etc/shadow"},
        ),
    )
    return a_report(
        server_command="python server.py",
        tool_reports=[a_run_command_tool_report(cases=[unjudged])],
    )


def a_report_with_an_unjudged_chain() -> AuditReport:
    return a_report(
        server_command="python server.py",
        tool_reports=[a_run_command_tool_report(chains=[a_chain()])],
    )
