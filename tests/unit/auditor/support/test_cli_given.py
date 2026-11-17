from mcp_auditor.domain import AuditReport, Severity, TestCase
from mcp_auditor.domain.models import CoverageGap, MissCause, MissedModelCall, ModelCallKind
from mcp_auditor.domain.server_liveness import Relaunch, RelaunchCause, UnsentCause
from tests.unit.auditor.support import test_models_given as models


def a_report(
    finding: Severity | None = None,
    missed: MissCause | None = None,
    coverage_gap: bool = False,
    relaunched: bool = False,
    calls_not_sent: bool = False,
) -> AuditReport:
    report = models.a_report(
        missed_model_calls=[_a_missed_judgment(missed)] if missed else None,
        coverage_gap=_a_gap(coverage_gap, calls_not_sent),
    )
    if relaunched:
        report.relaunches = [_a_successful_relaunch()]
    if finding is not None:
        report.tool_reports[0].cases.append(
            TestCase(
                payload=models.a_payload(), judge_result=models.a_judge_result(severity=finding)
            )
        )
    return report


def _a_gap(coverage_gap: bool, calls_not_sent: bool) -> CoverageGap | None:
    if calls_not_sent:
        return CoverageGap(
            requested_cases=10,
            received_cases=10,
            missing_categories=[],
            unsent_cases=2,
            unsent_cause=UnsentCause.TOOL_TIMING_OUT,
        )
    return models.a_coverage_gap() if coverage_gap else None


def _a_successful_relaunch() -> Relaunch:
    return Relaunch(
        tool_name="test_tool",
        arguments={},
        cause=RelaunchCause.LOST_CONNECTION,
        succeeded=True,
    )


def _a_missed_judgment(cause: MissCause) -> MissedModelCall:
    return MissedModelCall(
        tool_name="test_tool", kind=ModelCallKind.JUDGMENT, cause=cause, detail="missed"
    )
