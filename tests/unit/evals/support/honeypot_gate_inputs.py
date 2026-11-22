from evals.gate import Cell, DetectionCount
from evals.ground_truth import GroundTruth
from evals.metrics import HoneypotMetrics
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

VULNERABLE_CELL: Cell = ("get_user", AuditCategory.INPUT_VALIDATION)
SAFE_CELL: Cell = ("get_user", AuditCategory.INJECTION)
OTHER_VULNERABLE_CELL: Cell = ("get_user", AuditCategory.INFO_LEAKAGE)
OTHER_SAFE_CELL: Cell = ("get_user", AuditCategory.RESOURCE_ABUSE)


def metrics(
    recall: float = 0.9,
    precision: float = 0.9,
    consistency: float = 0.9,
    distribution_coverage: float = 0.9,
) -> HoneypotMetrics:
    return HoneypotMetrics(
        recall=recall,
        precision=precision,
        consistency=consistency,
        distribution_coverage=distribution_coverage,
    )


def detections(count: int = 3, runs: int = 3) -> DetectionCount:
    """Over the 8 planted FAIL cells of the merged ground truth."""
    return DetectionCount(detections=count, runs=runs, planted=8)


def a_ground_truth_with_two_cells_of_each_side() -> GroundTruth:
    return {
        **a_ground_truth(),
        OTHER_VULNERABLE_CELL: EvalVerdict.FAIL,
        OTHER_SAFE_CELL: EvalVerdict.PASS,
    }


def a_ground_truth() -> GroundTruth:
    return {VULNERABLE_CELL: EvalVerdict.FAIL, SAFE_CELL: EvalVerdict.PASS}
