from mcp_auditor.domain.models import (
    AuditCategory,
    AuditReport,
    CoverageGap,
    MissCause,
    MissedModelCall,
    ModelCallKind,
    Severity,
    ToolReport,
)
from mcp_auditor.domain.server_liveness import Relaunch, RelaunchCause, UnsentCause
from tests.unit.auditor.support import report_builders as reports
from tests.unit.auditor.support.coverage_gaps import a_gap_with_calls_not_sent


def a_complete_report() -> AuditReport:
    return _a_report()


def a_report_with_a_finding(severity: Severity) -> AuditReport:
    report = _a_report()
    _add_a_finding(report, severity)
    return report


def a_report_with_a_finding_and_a_missed_call(severity: Severity) -> AuditReport:
    report = a_report_with_a_missed_call(MissCause.PROVIDER_REFUSAL)
    _add_a_finding(report, severity)
    return report


def a_report_with_a_missed_call(cause: MissCause) -> AuditReport:
    return _a_report(missed_model_calls=[_a_missed_judgment(cause)])


def a_report_with_a_coverage_gap() -> AuditReport:
    return _a_report(
        coverage_gap=CoverageGap(
            requested_cases=10, received_cases=6, missing_categories=[AuditCategory.INJECTION]
        )
    )


def a_report_with_calls_not_sent() -> AuditReport:
    return _a_report(coverage_gap=a_gap_with_calls_not_sent(UnsentCause.TOOL_TIMING_OUT))


def a_relaunched_report() -> AuditReport:
    report = _a_report()
    report.relaunches = [
        Relaunch(
            tool_name="test_tool",
            arguments={},
            cause=RelaunchCause.LOST_CONNECTION,
            succeeded=True,
        )
    ]
    return report


def _add_a_finding(report: AuditReport, severity: Severity) -> None:
    report.tool_reports[0].cases.append(
        reports.a_failing_case("test_tool", severity, AuditCategory.INJECTION, "vuln")
    )


def _a_report(
    missed_model_calls: list[MissedModelCall] | None = None, coverage_gap: CoverageGap | None = None
) -> AuditReport:
    tool_report = ToolReport(tool=reports.a_tool_definition(), cases=[], coverage_gap=coverage_gap)
    report = reports.a_report(server_command="test", tool_reports=[tool_report])
    report.missed_model_calls = missed_model_calls or []
    return report


def _a_missed_judgment(cause: MissCause) -> MissedModelCall:
    return MissedModelCall(
        tool_name="test_tool", kind=ModelCallKind.JUDGMENT, cause=cause, detail="missed"
    )
