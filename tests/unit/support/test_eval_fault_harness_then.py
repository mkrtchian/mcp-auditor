from evals.fault_catalog import SEED
from evals.fault_injection import lose_detections
from evals.metrics import VerdictMap, aggregate_verdicts
from mcp_auditor.domain.models import AuditCategory, AuditReport, EvalVerdict, TokenUsage
from tests.unit.support.test_eval_fault_harness_given import MANY_TOOLS


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


def lost_as_drawn_at(verdicts: VerdictMap, audit_index: int) -> None:
    every_case_detected: VerdictMap = {
        (tool.name, category): EvalVerdict.FAIL for tool in MANY_TOOLS for category in AuditCategory
    }
    assert verdicts == lose_detections(every_case_detected, SEED, audit_index)
