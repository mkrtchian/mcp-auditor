from enum import StrEnum
from typing import Self

from pydantic import BaseModel, model_validator

from evals.ground_truth import GroundTruth
from evals.metrics import EvalMetrics, VerdictMap
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

Cell = tuple[str, AuditCategory]


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


class FlipCause(StrEnum):
    UNCOVERED = "uncovered"
    WRONG_VERDICT = "wrong_verdict"


class ReplayRule(BaseModel):
    replays: int = 5
    required: int = 4

    @model_validator(mode="after")
    def _decides_once_spent(self) -> Self:
        # Outside these bounds `decide` settles every flip before the first replay.
        if not 1 <= self.required <= self.replays:
            raise ValueError(
                f"replay rule needs 1 <= required <= replays, got {self.required} of {self.replays}"
            )
        return self

    def decide(self, reproduced: int, cleared: int) -> bool | None:
        if reproduced >= self.required:
            return True
        if cleared > self.replays - self.required:
            return False
        return None


FLOORS: dict[str, float] = {
    "recall": 0.50,
    "precision": 0.50,
    "distribution_coverage": 0.50,
}


def cell_key(cell: Cell) -> str:
    tool, category = cell
    return f"{tool}/{category.value}"


def parse_cell_key(key: str) -> Cell:
    tool, category = key.rsplit("/", 1)
    return tool, AuditCategory(category)


def observe(verdicts: VerdictMap, ground_truth: GroundTruth) -> dict[Cell, Observation]:
    return {cell: _observation_of(verdicts.get(cell)) for cell in ground_truth}


def _observation_of(verdict: EvalVerdict | None) -> Observation:
    return Observation.UNCOVERED if verdict is None else Observation(verdict.value)


def classify(
    runs: list[dict[Cell, Observation]], ground_truth: GroundTruth
) -> dict[Cell, CellState]:
    return {
        cell: _state_of([run.get(cell, Observation.UNCOVERED) for run in runs], expected)
        for cell, expected in ground_truth.items()
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
    replays: list[bool] = []


def compare(
    baseline_runs: list[dict[Cell, Observation]],
    candidate_runs: list[dict[Cell, Observation]],
    ground_truth: GroundTruth,
) -> dict[Cell, CellComparison]:
    baseline_states = classify(baseline_runs, ground_truth)
    candidate_states = classify(candidate_runs, ground_truth)
    return {
        cell: _compare_cell(
            baseline_states[cell],
            candidate_states[cell] == CellState.STABLE_CORRECT,
            _flip_cause(cell, candidate_runs),
        )
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


def _flip_cause(cell: Cell, candidate_runs: list[dict[Cell, Observation]]) -> FlipCause:
    uncovered = any(
        run.get(cell, Observation.UNCOVERED) == Observation.UNCOVERED for run in candidate_runs
    )
    return FlipCause.UNCOVERED if uncovered else FlipCause.WRONG_VERDICT


def settle(comparison: CellComparison, replays: list[bool], rule: ReplayRule) -> CellComparison:
    reproduced = sum(replays)
    regression = rule.decide(reproduced, len(replays) - reproduced)
    outcome = CellOutcome.REGRESSION if regression else CellOutcome.FLIP_NOT_REPRODUCED
    return comparison.model_copy(update={"outcome": outcome, "replays": list(replays)})


def floor_breaches(metrics: EvalMetrics) -> list[str]:
    return [name for name, floor in FLOORS.items() if getattr(metrics, name) < floor]


def metric_resolutions(
    verdict_maps: list[VerdictMap], ground_truth: GroundTruth, tool_count: int
) -> dict[str, float]:
    """One misclassified case's move on each averaged metric (ADR 016).

    Precision counts every predicted FAIL of the full maps, outside the ground truth
    included: the mean per map times the runs is their total.
    """
    runs = len(verdict_maps)
    expected_fails = sum(1 for verdict in ground_truth.values() if verdict == EvalVerdict.FAIL)
    predicted_fails = sum(
        1
        for verdicts in verdict_maps
        for verdict in verdicts.values()
        if verdict == EvalVerdict.FAIL
    )
    return {
        "recall": _one_case_in(expected_fails * runs),
        "precision": _one_case_in(predicted_fails),
        "distribution_coverage": _one_case_in(tool_count * len(AuditCategory) * runs),
    }


def _one_case_in(support: int) -> float:
    # No single case can move a metric that has no support.
    return 1 / support if support else 1.0


class MetricDelta(BaseModel):
    value: float
    resolution: float
    inconclusive: bool


def metric_deltas(
    baseline: EvalMetrics, candidate: EvalMetrics, resolutions: dict[str, float]
) -> dict[str, MetricDelta]:
    deltas: dict[str, MetricDelta] = {}
    for name in FLOORS:
        value: float = getattr(candidate, name) - getattr(baseline, name)
        resolution = resolutions[name]
        deltas[name] = MetricDelta(
            value=value, resolution=resolution, inconclusive=abs(value) < resolution
        )
    return deltas
