from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import BaseModel

from evals.baseline import BaselineStatus
from evals.declared_flips import held_declarations
from evals.gate import CellComparison, CellOutcome, ProtectedCells
from evals.gate_metrics import (
    FLOORS,
    LEGACY_THRESHOLDS,
    DetectionCount,
    MetricDelta,
    floor_breach_reason,
    floor_breaches,
    recall_breach_reason,
)
from evals.ground_truth import Cell, cell_key
from evals.metrics import HoneypotMetrics

NOT_COMPARABLE_EXIT = 3  # also the exit code of a refusal
CRASHED_EXIT = 4


class GateMode(StrEnum):
    LEGACY_THRESHOLDS = "legacy_thresholds"
    FLOORS_ONLY = "floors_only"
    PAIRED = "paired"


class GateOutcome(StrEnum):
    GREEN = "green"
    RED = "red"
    NOT_COMPARABLE = "not_comparable"

    @property
    def exit_code(self) -> int:
        match self:
            case GateOutcome.GREEN:
                return 0
            case GateOutcome.RED:
                return 1
            case GateOutcome.NOT_COMPARABLE:
                return NOT_COMPARABLE_EXIT


class GateResult(BaseModel):
    mode: GateMode
    outcome: GateOutcome
    reasons: list[str]
    baseline_status: BaselineStatus | None
    cells: dict[str, CellComparison]
    floors: dict[str, float]
    thresholds: dict[str, float]
    floor_breaches: list[str]
    deltas: dict[str, MetricDelta]
    protected: ProtectedCells | None = None
    declared_held: list[str] = []


@dataclass(frozen=True)
class GateInput:
    """Mismatches cover every reason the run cannot be compared."""

    mode: GateMode
    metrics: HoneypotMetrics
    detections: DetectionCount
    baseline_status: BaselineStatus | None = None
    cells: dict[Cell, CellComparison] = field(default_factory=dict[Cell, CellComparison])
    mismatches: list[str] = field(default_factory=list[str])
    deltas: dict[str, MetricDelta] = field(default_factory=dict[str, MetricDelta])
    protected: ProtectedCells | None = None
    declared: frozenset[Cell] = frozenset()


def decide_gate(gate_input: GateInput) -> GateResult:
    breaches = floor_breaches(gate_input.metrics, gate_input.detections)
    if gate_input.mismatches:
        outcome, reasons = GateOutcome.NOT_COMPARABLE, list(gate_input.mismatches)
    else:
        reasons = _red_reasons(gate_input, breaches)
        outcome = GateOutcome.RED if reasons else GateOutcome.GREEN
    return GateResult(
        mode=gate_input.mode,
        outcome=outcome,
        reasons=reasons,
        baseline_status=gate_input.baseline_status,
        cells={cell_key(cell): comparison for cell, comparison in gate_input.cells.items()},
        floors=_floors_of(gate_input.detections),
        thresholds=_thresholds_of(gate_input.mode),
        floor_breaches=breaches,
        deltas=gate_input.deltas,
        protected=gate_input.protected,
        declared_held=sorted(
            cell_key(cell) for cell in held_declarations(gate_input.cells, gate_input.declared)
        ),
    )


def _floors_of(count: DetectionCount) -> dict[str, float]:
    """Recall's floor as the mean it amounts to, for display: the count decides the breach."""
    return {"recall": 1 / count.planted, **FLOORS}


def _thresholds_of(mode: GateMode) -> dict[str, float]:
    return dict(LEGACY_THRESHOLDS) if mode == GateMode.LEGACY_THRESHOLDS else {}


def _red_reasons(gate_input: GateInput, breaches: list[str]) -> list[str]:
    match gate_input.mode:
        case GateMode.LEGACY_THRESHOLDS:
            return _missed_thresholds(gate_input.metrics)
        case GateMode.FLOORS_ONLY:
            return _breach_reasons(gate_input, breaches)
        case GateMode.PAIRED:
            return _breach_reasons(gate_input, breaches) + _regressions(gate_input.cells)


def _missed_thresholds(metrics: HoneypotMetrics) -> list[str]:
    return [
        f"{name} {getattr(metrics, name):.2f} under its threshold {threshold:.2f}"
        for name, threshold in LEGACY_THRESHOLDS.items()
        if getattr(metrics, name) < threshold
    ]


def _breach_reasons(gate_input: GateInput, breaches: list[str]) -> list[str]:
    return [_breach_reason(gate_input, name) for name in breaches]


def _breach_reason(gate_input: GateInput, name: str) -> str:
    if name == "recall":
        return recall_breach_reason(gate_input.detections)
    return floor_breach_reason(name, getattr(gate_input.metrics, name))


def _regressions(cells: dict[Cell, CellComparison]) -> list[str]:
    return [
        f"regression on {cell_key(cell)}"
        for cell, comparison in cells.items()
        if comparison.outcome == CellOutcome.REGRESSION
    ]
