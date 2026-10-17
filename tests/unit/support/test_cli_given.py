from mcp_auditor.domain import AuditReport, Severity, TestCase
from mcp_auditor.domain.models import AuditStep, MissCause, MissedStep
from tests.unit.support import test_models_given as models


def a_report(
    finding: Severity | None = None,
    missed: MissCause | None = None,
    coverage_gap: bool = False,
) -> AuditReport:
    report = models.a_report(
        missed_steps=[_a_missed_judgment(missed)] if missed else None,
        coverage_gap=models.a_coverage_gap() if coverage_gap else None,
    )
    if finding is not None:
        report.tool_reports[0].cases.append(
            TestCase(
                payload=models.a_payload(), eval_result=models.an_eval_result(severity=finding)
            )
        )
    return report


def _a_missed_judgment(cause: MissCause) -> MissedStep:
    return MissedStep(tool_name="test_tool", step=AuditStep.JUDGMENT, cause=cause, detail="missed")
