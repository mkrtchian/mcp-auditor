from evals.baseline import Baseline
from evals.gate import Cell, CellComparison, CellOutcome, FlipCause, cell_key
from evals.gate_verdict import GateResult, GateVerdict
from evals.recording import RecordingRefused


def red_on(result: GateResult, *reasons: str) -> None:
    assert result.verdict == GateVerdict.RED
    assert result.reasons == list(reasons)


def flipped(cells: dict[Cell, CellComparison], expected: list[Cell], cause: FlipCause) -> None:
    flips = {cell for cell, comparison in cells.items() if comparison.outcome == CellOutcome.FLIP}
    assert flips == set(expected)
    assert {cells[cell].cause for cell in flips} <= {cause}


def settled_as(result: GateResult, expected: list[Cell], outcome: CellOutcome) -> None:
    settled = {key for key, comparison in result.cells.items() if comparison.outcome == outcome}
    assert settled == {cell_key(cell) for cell in expected}


def refused_on(decision: Baseline | RecordingRefused, *breaches: str) -> None:
    assert isinstance(decision, RecordingRefused)
    assert decision.reasons == [f"{breach} under its floor" for breach in breaches]
