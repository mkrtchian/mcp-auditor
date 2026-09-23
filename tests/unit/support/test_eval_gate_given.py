from evals.gate import Cell, Observation
from evals.ground_truth import GroundTruth
from evals.metrics import EvalMetrics, VerdictMap
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

VULNERABLE_CELL: Cell = ("get_user", AuditCategory.INPUT_VALIDATION)
SAFE_CELL: Cell = ("get_user", AuditCategory.INJECTION)


def a_ground_truth() -> GroundTruth:
    return {VULNERABLE_CELL: EvalVerdict.FAIL, SAFE_CELL: EvalVerdict.PASS}


def runs_observing(cell: Cell, observations: list[Observation]) -> list[dict[Cell, Observation]]:
    return [{cell: observation} for observation in observations]


def metrics(
    recall: float = 0.9,
    precision: float = 0.9,
    consistency: float = 0.9,
    distribution_coverage: float = 0.9,
) -> EvalMetrics:
    return EvalMetrics(
        recall=recall,
        precision=precision,
        consistency=consistency,
        distribution_coverage=distribution_coverage,
    )


def runs_failing(cell: Cell, runs: int) -> list[VerdictMap]:
    return [{cell: EvalVerdict.FAIL} for _ in range(runs)]
