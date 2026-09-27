from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from evals.gate import (
    Cell,
    CellComparison,
    CellOutcome,
    CellState,
    Observation,
    cell_key,
    classify,
    parse_cell_key,
)
from evals.ground_truth import GroundTruth
from evals.honeypots import HoneypotConfig
from mcp_auditor.domain.models import AuditCategory, EvalVerdict


class CellTag(StrEnum):
    GATE = "gate"
    UNSTABLE = "unst"
    MISS = "miss"
    ALARM = "alarm"
    FLIP = "flip"
    REGRESSION = "REGR"
    FIXED = "fixed"
    NEW = "new"


@dataclass(frozen=True)
class GridBox:
    tag: CellTag
    planted: bool


@dataclass(frozen=True)
class GridRow:
    tool: str
    boxes: dict[AuditCategory, GridBox | None]  # None: no such cell


@dataclass(frozen=True)
class GridSection:
    honeypot: str
    rows: list[GridRow]


@dataclass(frozen=True)
class RunAgainstBaseline:
    comparisons: dict[str, CellComparison]  # GateResult.cells, keyed by cell_key
    runs: list[dict[Cell, Observation]]


@dataclass(frozen=True)
class OutcomeRow:
    outcome: CellOutcome
    cell: str
    planted: bool
    baseline: str
    run: str
    replays: str


@dataclass(frozen=True)
class GateGrid:
    title: str
    sections: list[GridSection]  # empty against an exploratory baseline
    outcomes: list[OutcomeRow]


def cell_grid(
    honeypots: Sequence[HoneypotConfig],
    baseline_runs: list[dict[Cell, Observation]],
    run: RunAgainstBaseline | None = None,
) -> list[GridSection]:
    return [
        GridSection(honeypot.name, _rows(honeypot.ground_truth, baseline_runs, run))
        for honeypot in honeypots
    ]


def outcome_rows(
    ground_truth: GroundTruth,
    baseline_runs: list[dict[Cell, Observation]],
    run: RunAgainstBaseline,
) -> list[OutcomeRow]:
    return [
        OutcomeRow(
            outcome=comparison.outcome,
            cell=key,
            planted=ground_truth.get(parse_cell_key(key)) == EvalVerdict.FAIL,
            baseline=_letters(parse_cell_key(key), baseline_runs),
            run=_letters(parse_cell_key(key), run.runs),
            replays=_replays(comparison.replays),
        )
        for key, comparison in sorted(run.comparisons.items())
        if comparison.outcome != CellOutcome.UNCHANGED
    ]


_OUTCOME_TAGS: dict[CellOutcome, CellTag] = {
    CellOutcome.FLIP: CellTag.FLIP,
    CellOutcome.FLIP_NOT_REPRODUCED: CellTag.FLIP,
    CellOutcome.REGRESSION: CellTag.REGRESSION,
    CellOutcome.IMPROVED: CellTag.FIXED,
    CellOutcome.NOT_RECORDED: CellTag.NEW,
}


def _rows(
    ground_truth: GroundTruth,
    baseline_runs: list[dict[Cell, Observation]],
    run: RunAgainstBaseline | None,
) -> list[GridRow]:
    states = classify(baseline_runs, ground_truth)
    tools = dict.fromkeys(tool for tool, _ in ground_truth)
    return [
        GridRow(
            tool,
            {
                category: _box((tool, category), ground_truth, states, run)
                if (tool, category) in ground_truth
                else None
                for category in AuditCategory
            },
        )
        for tool in tools
    ]


def _box(
    cell: Cell,
    ground_truth: GroundTruth,
    states: dict[Cell, CellState],
    run: RunAgainstBaseline | None,
) -> GridBox:
    planted = ground_truth[cell] == EvalVerdict.FAIL
    tag = _baseline_tag(states.get(cell), planted)
    comparison = run.comparisons.get(cell_key(cell)) if run else None
    if comparison is not None:
        tag = _OUTCOME_TAGS.get(comparison.outcome, tag)
    return GridBox(tag, planted)


def _baseline_tag(state: CellState | None, planted: bool) -> CellTag:
    match state:
        case CellState.STABLE_CORRECT:
            return CellTag.GATE
        case CellState.UNSTABLE:
            return CellTag.UNSTABLE
        case CellState.STABLE_INCORRECT:
            return CellTag.MISS if planted else CellTag.ALARM
        case None:
            return CellTag.NEW


def _letters(cell: Cell, runs: list[dict[Cell, Observation]]) -> str:
    return "".join(_LETTERS[run.get(cell, Observation.UNCOVERED)] for run in runs)


_LETTERS = {Observation.PASS: "P", Observation.FAIL: "F", Observation.UNCOVERED: "-"}


def _replays(replays: list[bool]) -> str:
    return f"{sum(replays)}/{len(replays)}" if replays else "-"
