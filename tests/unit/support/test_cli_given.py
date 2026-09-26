from mcp_auditor.domain import AuditReport, Severity, TestCase
from tests.unit.support import test_models_given as models


def a_report(
    finding: Severity | None = None, refused: bool = False, coverage_gap: bool = False
) -> AuditReport:
    report = models.a_report(
        refused_steps=[models.a_refused_step()] if refused else None,
        coverage_gap=models.a_coverage_gap() if coverage_gap else None,
    )
    if finding is not None:
        report.tool_reports[0].cases.append(
            TestCase(
                payload=models.a_payload(), eval_result=models.an_eval_result(severity=finding)
            )
        )
    return report
