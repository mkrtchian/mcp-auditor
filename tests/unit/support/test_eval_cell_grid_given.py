from pathlib import Path

from evals.cell_grid import RunAgainstBaseline
from evals.gate import Cell, CellComparison, CellOutcome, Observation, cell_key
from evals.ground_truth import GroundTruth
from evals.honeypots import HoneypotConfig
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

PLANTED_CELL: Cell = ("write_file", AuditCategory.INJECTION)
SAFE_CELL: Cell = ("list_dir", AuditCategory.ERROR_HANDLING)
OTHER_SAFE_CELL: Cell = ("write_file", AuditCategory.INPUT_VALIDATION)
SECOND_PLANTED_CELL: Cell = ("query", AuditCategory.INFO_LEAKAGE)
SECOND_SAFE_CELL: Cell = ("query", AuditCategory.INJECTION)

# The tools interleave so that row order follows first appearance, not alphabetical order.
FILES_GROUND_TRUTH: GroundTruth = {
    PLANTED_CELL: EvalVerdict.FAIL,
    SAFE_CELL: EvalVerdict.PASS,
    OTHER_SAFE_CELL: EvalVerdict.PASS,
}
DATABASE_GROUND_TRUTH: GroundTruth = {
    SECOND_PLANTED_CELL: EvalVerdict.FAIL,
    SECOND_SAFE_CELL: EvalVerdict.PASS,
}
MERGED_GROUND_TRUTH: GroundTruth = {**FILES_GROUND_TRUTH, **DATABASE_GROUND_TRUTH}

Runs = list[dict[Cell, Observation]]


def honeypots() -> list[HoneypotConfig]:
    return [
        HoneypotConfig("files", Path("unused.py"), FILES_GROUND_TRUTH),
        HoneypotConfig("database", Path("unused.py"), DATABASE_GROUND_TRUTH),
    ]


def baseline_runs(
    overrides: dict[Cell, list[Observation | None]] | None = None, runs: int = 3
) -> Runs:
    """Every cell observed correctly in every run, except the overridden ones, where None
    means that run lacks the cell."""
    sequences: dict[Cell, list[Observation | None]] = {
        cell: [Observation(expected.value)] * runs for cell, expected in MERGED_GROUND_TRUTH.items()
    }
    sequences.update(overrides or {})
    return [
        {
            cell: observation
            for cell, seen in sequences.items()
            if (observation := seen[index]) is not None
        }
        for index in range(runs)
    ]


def a_run(comparisons: dict[Cell, CellComparison], runs: Runs | None = None) -> RunAgainstBaseline:
    return RunAgainstBaseline(
        comparisons={cell_key(cell): comparison for cell, comparison in comparisons.items()},
        runs=runs if runs is not None else baseline_runs(),
    )


def comparison(outcome: CellOutcome, replays: list[bool] | None = None) -> CellComparison:
    return CellComparison(outcome=outcome, replays=replays or [])
