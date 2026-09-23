from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import BaseModel

from evals.baseline import BaselineStatus
from evals.gate import (
    FLOORS,
    LEGACY_THRESHOLDS,
    Cell,
    CellComparison,
    CellOutcome,
    MetricDelta,
    cell_key,
    floor_breaches,
)
from evals.metrics import EvalMetrics


class GateMode(StrEnum):
    LEGACY_THRESHOLDS = "legacy_thresholds"
    FLOORS_ONLY = "floors_only"
    PAIRED = "paired"


class GateVerdict(StrEnum):
    GREEN = "green"
    RED = "red"
    NOT_COMPARABLE = "not_comparable"


class GateResult(BaseModel):
    mode: GateMode
    verdict: GateVerdict
    reasons: list[str]
    baseline_status: BaselineStatus | None
    cells: dict[str, CellComparison]
    floors: dict[str, float]
    thresholds: dict[str, float]
    floor_breaches: list[str]
    deltas: dict[str, MetricDelta]


@dataclass(frozen=True)
class GateInput:
    """Mismatches cover every reason the run cannot be compared."""

    mode: GateMode
    metrics: EvalMetrics
    baseline_status: BaselineStatus | None = None
    cells: dict[Cell, CellComparison] = field(default_factory=dict[Cell, CellComparison])
    mismatches: list[str] = field(default_factory=list[str])
    deltas: dict[str, MetricDelta] = field(default_factory=dict[str, MetricDelta])


def judge_gate(gate_input: GateInput) -> GateResult:
    breaches = floor_breaches(gate_input.metrics)
    if gate_input.mismatches:
        verdict, reasons = GateVerdict.NOT_COMPARABLE, list(gate_input.mismatches)
    else:
        reasons = _red_reasons(gate_input, breaches)
        verdict = GateVerdict.RED if reasons else GateVerdict.GREEN
    return GateResult(
        mode=gate_input.mode,
        verdict=verdict,
        reasons=reasons,
        baseline_status=gate_input.baseline_status,
        cells={cell_key(cell): comparison for cell, comparison in gate_input.cells.items()},
        floors=dict(FLOORS),
        thresholds=_thresholds_of(gate_input.mode),
        floor_breaches=breaches,
        deltas=gate_input.deltas,
    )


def _thresholds_of(mode: GateMode) -> dict[str, float]:
    return dict(LEGACY_THRESHOLDS) if mode == GateMode.LEGACY_THRESHOLDS else {}


def _red_reasons(gate_input: GateInput, breaches: list[str]) -> list[str]:
    match gate_input.mode:
        case GateMode.LEGACY_THRESHOLDS:
            return _missed_thresholds(gate_input.metrics)
        case GateMode.FLOORS_ONLY:
            return _breach_reasons(gate_input.metrics, breaches)
        case GateMode.PAIRED:
            return _breach_reasons(gate_input.metrics, breaches) + _regressions(gate_input.cells)


def _missed_thresholds(metrics: EvalMetrics) -> list[str]:
    return [
        f"{name} {getattr(metrics, name):.2f} under its threshold {threshold:.2f}"
        for name, threshold in LEGACY_THRESHOLDS.items()
        if getattr(metrics, name) < threshold
    ]


def _breach_reasons(metrics: EvalMetrics, breaches: list[str]) -> list[str]:
    return [
        f"{name} {getattr(metrics, name):.2f} under its floor {FLOORS[name]:.2f}"
        for name in breaches
    ]


def _regressions(cells: dict[Cell, CellComparison]) -> list[str]:
    return [
        f"regression on {cell_key(cell)}"
        for cell, comparison in cells.items()
        if comparison.outcome == CellOutcome.REGRESSION
    ]
