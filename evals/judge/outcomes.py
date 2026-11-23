"""The case comparison of a judge run as the console shows it: a count per outcome, the cases
that left `unchanged`, and the `unchanged` ones wrong in every baseline run and right in some runs
of this one (`partial`)."""

from dataclasses import dataclass

from evals.cell_grid import (
    PARTIAL,
    DisplayedOutcome,
    observation_letters,
    partial_improvements,
)
from evals.gate import CellOutcome, Observation
from evals.ground_truth import cell_key
from evals.judge.fixture import CaseLabel, JudgeCase, JudgeFixture, ground_truth_of
from evals.judge.session_model import JudgeSessionResult


@dataclass(frozen=True)
class JudgeOutcomeRow:
    outcome: DisplayedOutcome
    case: str
    origin: str
    tool_category: str
    label: CaseLabel | None
    baseline: str
    run: str
    retests: str
    cause: str


@dataclass(frozen=True)
class CaseOutcomes:
    rows: list[JudgeOutcomeRow]
    counts: dict[DisplayedOutcome, int]


def case_outcomes(result: JudgeSessionResult, fixture: JudgeFixture) -> CaseOutcomes:
    if result.baseline is None:
        return CaseOutcomes(rows=[], counts={})
    outcomes = _displayed_outcomes(result, fixture)
    return CaseOutcomes(_rows(outcomes, result, fixture), _counts(outcomes))


def _rows(
    outcomes: dict[str, DisplayedOutcome], result: JudgeSessionResult, fixture: JudgeFixture
) -> list[JudgeOutcomeRow]:
    cases = {case.id: case for case in fixture.cases}
    rows = [
        _row(cases[case], outcome, result)
        for case, outcome in outcomes.items()
        if outcome != CellOutcome.UNCHANGED
    ]
    return sorted(rows, key=lambda row: (_OUTCOME_ORDER.index(row.outcome), row.case))


def _counts(outcomes: dict[str, DisplayedOutcome]) -> dict[DisplayedOutcome, int]:
    displayed = list(outcomes.values())
    return {outcome: displayed.count(outcome) for outcome in _OUTCOME_ORDER if outcome in displayed}


_OUTCOME_ORDER: list[DisplayedOutcome] = list(CellOutcome)
_OUTCOME_ORDER.insert(_OUTCOME_ORDER.index(CellOutcome.IMPROVED) + 1, PARTIAL)


def _displayed_outcomes(
    result: JudgeSessionResult, fixture: JudgeFixture
) -> dict[str, DisplayedOutcome]:
    partial = partial_improvements(result.baseline_runs, result.runs, ground_truth_of(fixture))
    return {
        case: PARTIAL
        if comparison.outcome == CellOutcome.UNCHANGED and case in partial
        else comparison.outcome
        for case, comparison in result.gate.cases.items()
    }


def _row(case: JudgeCase, outcome: DisplayedOutcome, result: JudgeSessionResult) -> JudgeOutcomeRow:
    comparison = result.gate.cases[case.id]
    return JudgeOutcomeRow(
        outcome=outcome,
        case=case.id,
        origin=case.origin,
        tool_category=cell_key((case.inputs.tool_name, case.inputs.category)),
        label=case.label,
        baseline=_letters(case.id, result.baseline_runs),
        run=_letters(case.id, result.runs),
        retests=observation_letters(result.retest_observations.get(case.id, [])) or "-",
        cause=comparison.cause.value if comparison.cause else "-",
    )


def _letters(case: str, runs: list[dict[str, Observation]]) -> str:
    return observation_letters(run.get(case, Observation.UNCOVERED) for run in runs)
