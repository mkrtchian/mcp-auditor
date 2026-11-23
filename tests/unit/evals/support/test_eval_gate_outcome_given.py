import tests.unit.evals.support.honeypot_gate_inputs as honeypot_gate_inputs
from evals.gate import CellComparison, CellOutcome
from evals.gate_metrics import DetectionCount
from evals.gate_outcome import GateInput, GateMode
from evals.ground_truth import Cell
from evals.metrics import HoneypotMetrics
from mcp_auditor.domain.models import AuditCategory


def a_gate_input(
    mode: GateMode,
    *,
    metrics: HoneypotMetrics | None = None,
    detections: DetectionCount | None = None,
    cells: dict[Cell, CellComparison] | None = None,
    mismatches: list[str] | None = None,
    declared: frozenset[Cell] = frozenset(),
) -> GateInput:
    """A run that clears every floor, one detection per run, unless an argument says otherwise."""
    return GateInput(
        mode=mode,
        metrics=metrics or honeypot_gate_inputs.metrics(),
        detections=detections or honeypot_gate_inputs.detections(),
        cells=cells or {},
        mismatches=mismatches or [],
        declared=declared,
    )


def cells_with(*outcomes: CellOutcome) -> dict[Cell, CellComparison]:
    return {cell(index): CellComparison(outcome=outcome) for index, outcome in enumerate(outcomes)}


def cell(index: int) -> Cell:
    return f"tool_{index}", AuditCategory.INPUT_VALIDATION
