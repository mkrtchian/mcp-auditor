from evals.gate import CellComparison, CellOutcome
from evals.ground_truth import Cell
from mcp_auditor.domain.models import AuditCategory


def cells_with(*outcomes: CellOutcome) -> dict[Cell, CellComparison]:
    return {cell(index): CellComparison(outcome=outcome) for index, outcome in enumerate(outcomes)}


def cell(index: int) -> Cell:
    return f"tool_{index}", AuditCategory.INPUT_VALIDATION
