"""The case comparison of a judge run as the console shows it: a count per outcome and the
cases that left `unchanged`."""

from dataclasses import dataclass

from evals.cell_grid import observation_letters
from evals.gate import CellComparison, CellOutcome, Observation
from evals.judge_fixture import CaseLabel, JudgeCase, JudgeFixture
from evals.judge_session import JudgeSessionResult


@dataclass(frozen=True)
class JudgeOutcomeRow:
    outcome: CellOutcome
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
    counts: dict[CellOutcome, int]


def case_outcomes(result: JudgeSessionResult, fixture: JudgeFixture) -> CaseOutcomes:
    return CaseOutcomes(judge_outcome_rows(result, fixture), outcome_counts(result))


def judge_outcome_rows(result: JudgeSessionResult, fixture: JudgeFixture) -> list[JudgeOutcomeRow]:
    if result.baseline is None:
        return []
    cases = {case.id: case for case in fixture.cases}
    rows = [
        _row(cases[case], comparison, result)
        for case, comparison in result.gate.cases.items()
        if comparison.outcome != CellOutcome.UNCHANGED
    ]
    return sorted(rows, key=lambda row: (_OUTCOME_ORDER.index(row.outcome), row.case))


def outcome_counts(result: JudgeSessionResult) -> dict[CellOutcome, int]:
    if result.baseline is None:
        return {}
    outcomes = [comparison.outcome for comparison in result.gate.cases.values()]
    return {outcome: outcomes.count(outcome) for outcome in CellOutcome if outcome in outcomes}


_OUTCOME_ORDER = list(CellOutcome)


def _row(
    case: JudgeCase, comparison: CellComparison, result: JudgeSessionResult
) -> JudgeOutcomeRow:
    baseline_runs = result.baseline.runs if result.baseline else []
    return JudgeOutcomeRow(
        outcome=comparison.outcome,
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
