from enum import StrEnum
from typing import Self

from pydantic import AliasChoices, BaseModel, Field, model_validator

from evals.ground_truth import Cell, GroundTruth
from evals.metrics import VerdictMap
from mcp_auditor.domain.models import EvalVerdict


class Observation(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNCOVERED = "uncovered"


class CellState(StrEnum):
    STABLE_CORRECT = "stable_correct"
    STABLE_INCORRECT = "stable_incorrect"
    UNSTABLE = "unstable"


class CellOutcome(StrEnum):
    UNCHANGED = "unchanged"
    IMPROVED = "improved"
    INCONCLUSIVE = "inconclusive"
    FLIP = "flip"
    REGRESSION = "regression"
    FLIP_NOT_REPRODUCED = "flip_not_reproduced"
    NOT_RECORDED = "not_recorded"
    DECLARED = "declared"


class FlipCause(StrEnum):
    UNCOVERED = "uncovered"
    WRONG_VERDICT = "wrong_verdict"


class RetestRule(BaseModel):
    """A flip is a regression when it reproduces 4 times out of at most 5 retests, stopping
    as soon as the outcome is decided.

    Blind spot: a judge that loses each detection half the time reproduces a flip with
    probability 6/32, about 0.19, so the gate misses most such losses. The evidence is in
    `evals/fault_injection_method.md`.
    """

    # Read from `replays` too, the key of the committed baselines until their next re-recording.
    retests: int = Field(default=5, validation_alias=AliasChoices("retests", "replays"))
    required: int = 4

    @model_validator(mode="after")
    def _decides_once_spent(self) -> Self:
        # Outside these bounds `decide` settles every flip before the first retest.
        if not 1 <= self.required <= self.retests:
            raise ValueError(
                f"retest rule needs 1 <= required <= retests, got {self.required} of {self.retests}"
            )
        return self

    def decide(self, reproduced: int, cleared: int) -> bool | None:
        if reproduced >= self.required:
            return True
        if cleared > self.retests - self.required:
            return False
        return None

    def decide_retests(self, retests: list[bool]) -> bool | None:
        reproduced = sum(retests)
        return self.decide(reproduced, len(retests) - reproduced)


def observe(verdicts: VerdictMap, ground_truth: GroundTruth) -> dict[Cell, Observation]:
    return {cell: _observation_of(verdicts.get(cell)) for cell in ground_truth}


def _observation_of(verdict: EvalVerdict | None) -> Observation:
    return Observation.UNCOVERED if verdict is None else Observation(verdict.value)


class ProtectedCells(BaseModel):
    """The stable and correct cells are the ones the paired comparison can see move (ADR 022)."""

    fail_stable_correct: int
    fail_total: int
    pass_stable_correct: int
    pass_total: int
    unstable: int


def protected_cells[K](
    runs: list[dict[K, Observation]], ground_truth: dict[K, EvalVerdict]
) -> ProtectedCells:
    states = classify(runs, ground_truth)

    def count(label: EvalVerdict, state: CellState | None = None) -> int:
        return sum(
            1
            for cell, seen in states.items()
            if ground_truth[cell] == label and state in (None, seen)
        )

    return ProtectedCells(
        fail_stable_correct=count(EvalVerdict.FAIL, CellState.STABLE_CORRECT),
        fail_total=count(EvalVerdict.FAIL),
        pass_stable_correct=count(EvalVerdict.PASS, CellState.STABLE_CORRECT),
        pass_total=count(EvalVerdict.PASS),
        unstable=sum(1 for state in states.values() if state == CellState.UNSTABLE),
    )


def classify[K](
    runs: list[dict[K, Observation]], ground_truth: dict[K, EvalVerdict]
) -> dict[K, CellState]:
    """Cells a run did not record get no state (ADR 020)."""
    return {
        cell: _state_of([run[cell] for run in runs], expected)
        for cell, expected in ground_truth.items()
        if all(cell in run for run in runs)
    }


def _state_of(observations: list[Observation], expected: EvalVerdict) -> CellState:
    if len(set(observations)) > 1:
        return CellState.UNSTABLE
    if observations[0] == Observation(expected.value):
        return CellState.STABLE_CORRECT
    return CellState.STABLE_INCORRECT


class CellComparison(BaseModel):
    outcome: CellOutcome
    cause: FlipCause | None = None
    retests: list[bool] = []


def compare[K](
    baseline_runs: list[dict[K, Observation]],
    candidate_runs: list[dict[K, Observation]],
    ground_truth: dict[K, EvalVerdict],
) -> dict[K, CellComparison]:
    baseline_states = classify(baseline_runs, ground_truth)
    candidate_states = classify(candidate_runs, ground_truth)
    return {
        cell: _compare_cell(
            baseline_states[cell],
            candidate_states[cell] == CellState.STABLE_CORRECT,
            _flip_cause(cell, candidate_runs),
        )
        if cell in baseline_states
        else CellComparison(outcome=CellOutcome.NOT_RECORDED)
        for cell in ground_truth
    }


def _compare_cell(
    baseline: CellState, candidate_always_correct: bool, cause: FlipCause
) -> CellComparison:
    match baseline:
        case CellState.STABLE_CORRECT if not candidate_always_correct:
            return CellComparison(outcome=CellOutcome.FLIP, cause=cause)
        case CellState.STABLE_INCORRECT if candidate_always_correct:
            return CellComparison(outcome=CellOutcome.IMPROVED)
        case CellState.UNSTABLE if not candidate_always_correct:
            return CellComparison(outcome=CellOutcome.INCONCLUSIVE)
        case _:
            return CellComparison(outcome=CellOutcome.UNCHANGED)


def _flip_cause[K](cell: K, candidate_runs: list[dict[K, Observation]]) -> FlipCause:
    uncovered = any(
        run.get(cell, Observation.UNCOVERED) == Observation.UNCOVERED for run in candidate_runs
    )
    return FlipCause.UNCOVERED if uncovered else FlipCause.WRONG_VERDICT


def apply_retests(
    comparison: CellComparison, retests: list[bool], rule: RetestRule
) -> CellComparison:
    regression = rule.decide_retests(retests)
    outcome = CellOutcome.REGRESSION if regression else CellOutcome.FLIP_NOT_REPRODUCED
    return comparison.model_copy(update={"outcome": outcome, "retests": list(retests)})
