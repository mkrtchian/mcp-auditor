from io import StringIO
from types import ModuleType

import pytest
from rich.console import Console

import tests.unit.support.test_eval_baseline_given as baseline_given
from evals import eval_display
from evals.cell_grid import CellTag, GateGrid, GridBox, GridRow, GridSection, OutcomeRow
from evals.gate_outcome import GateMode, GateOutcome, GateResult
from evals.honeypot.report import HoneypotReport
from evals.metrics import HoneypotMetrics
from mcp_auditor.domain.models import AuditCategory


def a_captured_console(
    monkeypatch: pytest.MonkeyPatch, *modules: ModuleType, width: int = 200
) -> StringIO:
    buffer = StringIO()
    shared = Console(file=buffer, width=width)
    for module in (eval_display, *modules):
        monkeypatch.setattr(module, "console", shared)
    return buffer


def an_eval_report(
    config: dict[str, int] | None = None, declared_held: list[str] | None = None
) -> HoneypotReport:
    return HoneypotReport(
        timestamp="2026-09-28T00:00:00+00:00",
        commit="c0ffee",
        dirty=False,
        conditions=baseline_given.conditions(),
        config=config or {"concurrency": 6},
        metrics=HoneypotMetrics(
            recall=1.0, precision=1.0, consistency=1.0, distribution_coverage=1.0
        ),
        thresholds={},
        passed=True,
        gate=GateResult(
            mode=GateMode.FLOORS_ONLY,
            outcome=GateOutcome.GREEN,
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
        retests="-",
    )
    return GateGrid(title="Baseline", sections=[], outcomes=[row])


def a_grid_tagging(*tags: CellTag) -> list[GridSection]:
    categories = list(AuditCategory)
    boxes: dict[AuditCategory, GridBox | None] = {category: None for category in categories}
    for category, tag in zip(categories, tags, strict=False):
        boxes[category] = GridBox(tag=tag, planted=False)
    return [GridSection(honeypot="honeypot", rows=[GridRow(tool="get_user", boxes=boxes)])]
