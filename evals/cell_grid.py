from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal

from evals.gate import CellComparison, CellOutcome, CellState, Observation, classify
from evals.ground_truth import Cell, GroundTruth, cell_key
from evals.honeypots import HoneypotConfig
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

PARTIAL: Final = "partial"

DisplayedOutcome = CellOutcome | Literal["partial"]


class CellTag(StrEnum):
    GATE = "gate"
    UNSTABLE = "unst"
    MISS = "miss"
    FALSE_POSITIVE = "false_positive"
    FLIP = "flip"
    DECLARED = "decl"
    REGRESSION = "REGR"
    IMPROVED = "improved"
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
    comparisons: dict[Cell, CellComparison]
    runs: list[dict[Cell, Observation]]


@dataclass(frozen=True)
class OutcomeRow:
    outcome: DisplayedOutcome
    cell: str
    planted: bool
    baseline: str
    run: str
    retests: str


@dataclass(frozen=True)
class GateGrid:
    title: str
    sections: list[GridSection]  # empty against an unconfirmed baseline
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
    partial = {
        cell
        for cell, comparison in run.comparisons.items()
        if comparison.outcome == CellOutcome.UNCHANGED
    } & partial_improvements(baseline_runs, run.runs, ground_truth)
    return [
        OutcomeRow(
            outcome=PARTIAL if cell in partial else comparison.outcome,
            cell=cell_key(cell),
            planted=ground_truth.get(cell) == EvalVerdict.FAIL,
            baseline=_letters(cell, baseline_runs),
            run=_letters(cell, run.runs),
            retests=retest_fraction(comparison.retests),
        )
        for cell, comparison in sorted(run.comparisons.items(), key=lambda item: cell_key(item[0]))
        if comparison.outcome != CellOutcome.UNCHANGED or cell in partial
    ]


def partial_improvements[K](
    baseline_runs: list[dict[K, Observation]],
    candidate_runs: list[dict[K, Observation]],
    ground_truth: dict[K, EvalVerdict],
) -> set[K]:
    """Cells wrong in every baseline run and right in some, not all, candidate runs."""
    states = classify(baseline_runs, ground_truth)
    return {
        key
        for key, state in states.items()
        if state == CellState.STABLE_INCORRECT
        and _right_in_some_not_all(key, candidate_runs, Observation.of(ground_truth[key]))
    }


def _right_in_some_not_all[K](
    key: K, runs: list[dict[K, Observation]], expected: Observation
) -> bool:
    right = [run.get(key, Observation.UNCOVERED) == expected for run in runs]
    return any(right) and not all(right)


_OUTCOME_TAGS: dict[CellOutcome, CellTag] = {
    CellOutcome.FLIP: CellTag.FLIP,
    CellOutcome.FLIP_NOT_REPRODUCED: CellTag.FLIP,
    CellOutcome.REGRESSION: CellTag.REGRESSION,
    CellOutcome.DECLARED: CellTag.DECLARED,
    CellOutcome.IMPROVED: CellTag.IMPROVED,
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
                category: _box(
                    (tool, category),
                    ground_truth,
                    states,
                    run.comparisons.get((tool, category)) if run else None,
                )
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
    comparison: CellComparison | None,
) -> GridBox:
    planted = ground_truth[cell] == EvalVerdict.FAIL
    tag = _baseline_tag(states.get(cell), planted)
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
            return CellTag.MISS if planted else CellTag.FALSE_POSITIVE
        case None:
            return CellTag.NEW


def _letters(cell: Cell, runs: list[dict[Cell, Observation]]) -> str:
    return observation_letters(run.get(cell, Observation.UNCOVERED) for run in runs)


def observation_letters(observations: Iterable[Observation]) -> str:
    return "".join(_LETTERS[observation] for observation in observations)


_LETTERS = {Observation.PASS: "P", Observation.FAIL: "F", Observation.UNCOVERED: "-"}


def retest_fraction(retests: Sequence[bool]) -> str:
    return f"{sum(retests)}/{len(retests)}" if retests else "-"
