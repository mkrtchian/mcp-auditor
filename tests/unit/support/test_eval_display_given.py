from io import StringIO

import pytest
from rich.console import Console

import tests.unit.support.test_eval_baseline_given as baseline_given
from evals import eval_display
from evals.cell_grid import GateGrid, OutcomeRow
from evals.eval_report import EvalReport
from evals.gate_verdict import GateMode, GateResult, GateVerdict
from evals.metrics import EvalMetrics


def a_captured_console(monkeypatch: pytest.MonkeyPatch) -> StringIO:
    buffer = StringIO()
    monkeypatch.setattr(eval_display, "console", Console(file=buffer, width=200))
    return buffer


def an_eval_report(
    config: dict[str, int] | None = None, declared_held: list[str] | None = None
) -> EvalReport:
    return EvalReport(
        timestamp="2026-09-28T00:00:00+00:00",
        commit="c0ffee",
        dirty=False,
        conditions=baseline_given.conditions(),
        config=config or {"concurrency": 6},
        metrics=EvalMetrics(recall=1.0, precision=1.0, consistency=1.0, distribution_coverage=1.0),
        thresholds={},
        passed=True,
        gate=GateResult(
            mode=GateMode.FLOORS_ONLY,
            verdict=GateVerdict.GREEN,
            reasons=[],
            baseline_status=None,
            cells={},
            floors={},
            thresholds={},
            floor_breaches=[],
            deltas={},
            declared_held=declared_held or [],
        ),
        runs=[],
        consistency_details={},
    )


def a_gate_grid_with_an_outcome_row(outcome: str) -> GateGrid:
    row = OutcomeRow(
        outcome=outcome,
        cell="list_dir/error_handling",
        planted=False,
        baseline="FFF",
        run="PFF",
        replays="-",
    )
    return GateGrid(title="Baseline", sections=[], outcomes=[row])
