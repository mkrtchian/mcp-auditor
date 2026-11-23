from evals.ground_truth import Cell, GroundTruth
from evals.metrics import VerdictMap
from mcp_auditor.domain.models import AuditCategory, EvalVerdict


def runs_failing(cell: Cell, runs: int) -> list[VerdictMap]:
    return [{cell: EvalVerdict.FAIL} for _ in range(runs)]


def a_run_failing(fails: int) -> VerdictMap:
    """A run predicting FAIL on that many cells, the cells of `a_ground_truth_failing`."""
    return {(f"tool_{index}", AuditCategory.INJECTION): EvalVerdict.FAIL for index in range(fails)}


def a_ground_truth_failing(cells: int) -> GroundTruth:
    return {(f"tool_{index}", AuditCategory.INJECTION): EvalVerdict.FAIL for index in range(cells)}
