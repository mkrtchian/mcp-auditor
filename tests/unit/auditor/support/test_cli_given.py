from mcp_auditor.domain import AuditReport, Severity, TestCase
from mcp_auditor.domain.models import MissCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.server_liveness import Relaunch, RelaunchCause, UnsentCause
from tests.unit.auditor.support import test_models_given as models
from tests.unit.auditor.support.coverage_gaps import a_gap_with_calls_not_sent


def a_complete_report() -> AuditReport:
    return models.a_report()


def a_report_with_a_finding(severity: Severity) -> AuditReport:
    report = models.a_report()
    _add_a_finding(report, severity)
    return report


def a_report_with_a_missed_call(cause: MissCause) -> AuditReport:
    return models.a_report(missed_model_calls=[_a_missed_judgment(cause)])


def a_report_with_a_finding_and_a_missed_call(severity: Severity) -> AuditReport:
    report = a_report_with_a_missed_call(MissCause.PROVIDER_REFUSAL)
    _add_a_finding(report, severity)
    return report


def a_report_with_a_coverage_gap() -> AuditReport:
    return models.a_report(coverage_gap=models.a_coverage_gap())


def a_report_with_calls_not_sent() -> AuditReport:
    return models.a_report(coverage_gap=a_gap_with_calls_not_sent(UnsentCause.TOOL_TIMING_OUT))


def a_relaunched_report() -> AuditReport:
    report = models.a_report()
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
        TestCase(payload=models.a_payload(), judge_result=models.a_judge_result(severity=severity))
    )


def _a_missed_judgment(cause: MissCause) -> MissedModelCall:
    return MissedModelCall(
        tool_name="test_tool", kind=ModelCallKind.JUDGMENT, cause=cause, detail="missed"
    )
