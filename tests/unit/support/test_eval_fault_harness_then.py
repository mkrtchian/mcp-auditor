from evals.metrics import VerdictMap, aggregate_verdicts
from mcp_auditor.domain.models import AuditReport, EvalVerdict, TokenUsage


def only_detections_lost(verdicts: VerdictMap, degraded: VerdictMap) -> None:
    turned = {cell for cell in verdicts if degraded[cell] != verdicts[cell]}
    assert turned
    assert {verdicts[cell] for cell in turned} == {EvalVerdict.FAIL}
    assert {degraded[cell] for cell in turned} == {EvalVerdict.PASS}


def merged(verdicts: VerdictMap, report: AuditReport, reports: list[AuditReport]) -> None:
    assert verdicts == {
        cell: verdict for each in reports for cell, verdict in aggregate_verdicts(each).items()
    }
    assert report.tool_reports == [tool for each in reports for tool in each.tool_reports]
    assert report.token_usage == TokenUsage(input_tokens=600, output_tokens=60)
    assert report.refused_steps == [step for each in reports for step in each.refused_steps]
