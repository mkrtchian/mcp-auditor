"""The case comparison of a judge run as the console shows it: a count per outcome, the cases
that left `unchanged`, and the `unchanged` ones wrong in every baseline run and right in some runs
of this one (`partial`)."""

from dataclasses import dataclass

from evals.cell_grid import PARTIAL, observation_letters, partial_improvements
from evals.gate import CellOutcome, Observation
from evals.judge_fixture import CaseLabel, JudgeCase, JudgeFixture, ground_truth_of
from evals.judge_session import JudgeSessionResult


@dataclass(frozen=True)
class JudgeOutcomeRow:
    outcome: str  # a CellOutcome, or PARTIAL
    case: str
    origin: str
    target: str  # tool/category
    label: CaseLabel | None
    baseline: str
    run: str
    replays: str
    cause: str


@dataclass(frozen=True)
class CaseOutcomes:
    rows: list[JudgeOutcomeRow]
    counts: dict[str, int]


def case_outcomes(result: JudgeSessionResult, fixture: JudgeFixture) -> CaseOutcomes:
    return CaseOutcomes(judge_outcome_rows(result, fixture), outcome_counts(result, fixture))


def judge_outcome_rows(result: JudgeSessionResult, fixture: JudgeFixture) -> list[JudgeOutcomeRow]:
    if result.baseline is None:
        return []
    cases = {case.id: case for case in fixture.cases}
    outcomes = _displayed_outcomes(result, fixture)
    rows = [
        _row(cases[case], outcome, result)
        for case, outcome in outcomes.items()
        if outcome != CellOutcome.UNCHANGED
    ]
    return sorted(rows, key=lambda row: (_OUTCOME_ORDER.index(row.outcome), row.case))


def outcome_counts(result: JudgeSessionResult, fixture: JudgeFixture) -> dict[str, int]:
    if result.baseline is None:
        return {}
    outcomes = list(_displayed_outcomes(result, fixture).values())
    return {outcome: outcomes.count(outcome) for outcome in _OUTCOME_ORDER if outcome in outcomes}


_OUTCOME_ORDER: list[str] = list(CellOutcome)
_OUTCOME_ORDER.insert(_OUTCOME_ORDER.index(CellOutcome.IMPROVED) + 1, PARTIAL)


def _displayed_outcomes(result: JudgeSessionResult, fixture: JudgeFixture) -> dict[str, str]:
    baseline_runs = result.baseline.runs if result.baseline else []
    partial = partial_improvements(baseline_runs, result.runs, ground_truth_of(fixture))
    return {
        case: PARTIAL
        if comparison.outcome == CellOutcome.UNCHANGED and case in partial
        else comparison.outcome
        for case, comparison in result.gate.cases.items()
    }


def _row(case: JudgeCase, outcome: str, result: JudgeSessionResult) -> JudgeOutcomeRow:
    comparison = result.gate.cases[case.id]
    baseline_runs = result.baseline.runs if result.baseline else []
    return JudgeOutcomeRow(
        outcome=outcome,
        case=case.id,
        origin=case.origin,
        target=f"{case.inputs.tool_name}/{case.inputs.category.value}",
        label=case.label,
        baseline=_letters(case.id, baseline_runs),
        run=_letters(case.id, result.runs),
        replays=observation_letters(result.replay_observations.get(case.id, [])) or "-",
        cause=comparison.cause.value if comparison.cause else "-",
    )


def _letters(case: str, runs: list[dict[str, Observation]]) -> str:
    return observation_letters(run.get(case, Observation.UNCOVERED) for run in runs)
