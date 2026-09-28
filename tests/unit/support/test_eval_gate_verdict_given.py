from evals.gate import Cell, CellComparison, CellOutcome
from mcp_auditor.domain.models import AuditCategory
from tests.unit.support.test_eval_gate_given import detections, metrics

__all__ = ["cell", "cells_with", "detections", "metrics"]


def cells_with(*outcomes: CellOutcome) -> dict[Cell, CellComparison]:
    return {cell(index): CellComparison(outcome=outcome) for index, outcome in enumerate(outcomes)}


def cell(index: int) -> Cell:
    return f"tool_{index}", AuditCategory.INPUT_VALIDATION
