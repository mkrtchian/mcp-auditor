from evals.gate import Observation
from evals.ground_truth import Cell
from tests.unit.evals.support.honeypot_gate_inputs import (
    OTHER_SAFE_CELL,
    OTHER_VULNERABLE_CELL,
    SAFE_CELL,
    VULNERABLE_CELL,
)


def runs_observing(cell: Cell, observations: list[Observation]) -> list[dict[Cell, Observation]]:
    return [{cell: observation} for observation in observations]


def runs_on_two_cells_of_each_side() -> list[dict[Cell, Observation]]:
    """Each side has one stable and correct cell: the other FAIL cell is unstable, the other
    PASS cell stable and incorrect."""
    return [
        {
            VULNERABLE_CELL: Observation.FAIL,
            OTHER_VULNERABLE_CELL: other_vulnerable,
            SAFE_CELL: Observation.PASS,
            OTHER_SAFE_CELL: Observation.FAIL,
        }
        for other_vulnerable in (Observation.FAIL, Observation.PASS, Observation.FAIL)
    ]
