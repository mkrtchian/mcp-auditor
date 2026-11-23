from evals.baseline import Baseline
from evals.ground_truth import Cell, cell_key
from tests.unit.evals.support.fault_injection_baseline import the_fault_injection_baseline


def the_fixture_missing(cell: Cell) -> Baseline:
    fixture = the_fault_injection_baseline()
    runs = [
        {key: seen for key, seen in run.items() if key != cell_key(cell)} for run in fixture.runs
    ]
    return fixture.model_copy(update={"runs": runs})
