from evals.honeypot.fault_catalog import SEED
from evals.honeypot.fault_injection import lose_detections
from evals.metrics import VerdictMap
from mcp_auditor.domain.models import AuditCategory, EvalVerdict
from tests.unit.evals.support.test_honeypot_fault_harness_given import MANY_TOOLS


def only_detections_lost(verdicts: VerdictMap, degraded: VerdictMap) -> None:
    turned = {cell for cell in verdicts if degraded[cell] != verdicts[cell]}
    assert turned
    assert {verdicts[cell] for cell in turned} == {EvalVerdict.FAIL}
    assert {degraded[cell] for cell in turned} == {EvalVerdict.PASS}


def lost_as_drawn_at(verdicts: VerdictMap, audit_index: int) -> None:
    every_case_detected: VerdictMap = {
        (tool.name, category): EvalVerdict.FAIL for tool in MANY_TOOLS for category in AuditCategory
    }
    assert verdicts == lose_detections(every_case_detected, SEED, audit_index)
