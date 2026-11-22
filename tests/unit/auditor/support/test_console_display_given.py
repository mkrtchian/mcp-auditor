from mcp_auditor.domain.model_calls import MissedCallCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    AuditReport,
    CoverageGap,
    ProviderUsage,
    Severity,
    ToolDefinition,
    ToolReport,
)
from mcp_auditor.domain.server_liveness import UnsentCause
from tests.unit.auditor.support.coverage_gaps import a_gap_with_calls_not_sent
from tests.unit.auditor.support.report_builders import a_failing_case, a_passing_case


def dry_run_payloads() -> list[AuditPayload]:
    return [
        AuditPayload(
            category=AuditCategory.INJECTION,
            description="SQL injection",
            arguments={"id": "1; DROP TABLE users"},
        ),
        AuditPayload(
            category=AuditCategory.INPUT_VALIDATION,
            description="Empty input",
            arguments={"id": ""},
        ),
    ]


def a_report_with_a_coverage_gap_on_get_user() -> AuditReport:
    report = a_report_with_two_tools()
    report.tool_reports[0].coverage_gap = CoverageGap(
        requested_cases=10,
        received_cases=7,
        missing_categories=[AuditCategory.INJECTION],
    )
    return report


def a_report_with_two_tools() -> AuditReport:
    return AuditReport(
        server_command="python server.py",
        tool_reports=[
            ToolReport(
                tool=ToolDefinition(name="get_user", description="", input_schema={}),
                cases=[a_passing_case("get_user")],
            ),
            ToolReport(
                tool=ToolDefinition(name="list_items", description="", input_schema={}),
                cases=[
                    a_failing_case(
                        "list_items", AuditCategory.INPUT_VALIDATION, Severity.HIGH, "bad"
                    ),
                ],
            ),
        ],
        provider_usage=ProviderUsage(input_tokens=1234, output_tokens=567),
    )


def a_report_with_calls_not_sent_on_get_user() -> AuditReport:
    report = a_report_with_two_tools()
    report.tool_reports[0].coverage_gap = a_gap_with_calls_not_sent(UnsentCause.TOOL_TIMING_OUT)
    return report


def a_report_throttled(throttled_requests: int) -> AuditReport:
    report = a_report_with_two_tools()
    report.provider_usage = ProviderUsage(
        input_tokens=1234, output_tokens=567, throttled_requests=throttled_requests
    )
    return report


REFUSAL_MESSAGE = "Invalid prompt: flagged as potentially violating our usage policy"


def a_report_with_a_refused_chain_planning() -> AuditReport:
    report = a_report_with_two_tools()
    report.missed_model_calls = [a_refused_chain_planning_on_list_items()]
    return report


def a_refused_chain_planning_on_list_items() -> MissedModelCall:
    return MissedModelCall(
        tool_name="list_items",
        kind=ModelCallKind.CHAIN_PLANNING,
        cause=MissedCallCause.PROVIDER_REFUSAL,
        detail=REFUSAL_MESSAGE,
    )
