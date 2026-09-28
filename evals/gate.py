import math
from dataclasses import dataclass
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
    NOT_RECORDED = "not_recorded"
    DECLARED = "declared"


class FlipCause(StrEnum):
    UNCOVERED = "uncovered"
    WRONG_VERDICT = "wrong_verdict"


class ReplayRule(BaseModel):
    """A flip is a regression when it reproduces 4 times out of at most 5 replays, stopping
    as soon as the outcome is decided.

    Blind spot: a judge that loses each detection half the time reproduces a flip with
    probability 6/32, about 0.19, so the gate misses most such losses. The evidence is in
    `evals/fault_injection_method.md`.
    """

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

    def decide_replays(self, replays: list[bool]) -> bool | None:
        reproduced = sum(replays)
        return self.decide(reproduced, len(replays) - reproduced)


FLOORS: dict[str, float] = {
    "precision": 0.50,
    "distribution_coverage": 0.50,
}

LEGACY_THRESHOLDS: dict[str, float] = {
    "recall": 0.80,
    "precision": 0.85,
    "consistency": 0.70,
    "distribution_coverage": 0.80,
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
    replays: list[bool] = []


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


def settle(comparison: CellComparison, replays: list[bool], rule: ReplayRule) -> CellComparison:
    regression = rule.decide_replays(replays)
    outcome = CellOutcome.REGRESSION if regression else CellOutcome.FLIP_NOT_REPRODUCED
    return comparison.model_copy(update={"outcome": outcome, "replays": list(replays)})


@dataclass(frozen=True)
class DetectionCount:
    detections: int  # planted FAIL cells observed FAIL, summed over the runs
    runs: int
    planted: int  # FAIL cells of the ground truth


def count_detections[K](
    runs: list[dict[K, Observation]], ground_truth: dict[K, EvalVerdict]
) -> DetectionCount:
    planted = [cell for cell, verdict in ground_truth.items() if verdict == EvalVerdict.FAIL]
    return DetectionCount(
        detections=sum(run.get(cell) == Observation.FAIL for run in runs for cell in planted),
        runs=len(runs),
        planted=len(planted),
    )


def recall_floor_breached(count: DetectionCount) -> bool:
    """One planted flaw found per run, on average (ADR 022): the collapse it catches, a judge
    that passes everything, finds none. A count, not a mean, so that no rounding decides it.
    A ground truth with no FAIL cell always breaches it: there is no flaw to find.
    """
    return count.detections < count.runs


def floor_breaches(metrics: EvalMetrics, count: DetectionCount) -> list[str]:
    recall = ["recall"] if recall_floor_breached(count) else []
    return recall + [name for name, floor in FLOORS.items() if getattr(metrics, name) < floor]


def metric_resolutions(
    verdict_maps: list[VerdictMap], ground_truth: GroundTruth, tool_count: int
) -> dict[str, float]:
    """One misclassified case's move on each averaged metric (ADR 016).

    Precision is averaged per run over that run's predicted FAILs on the cells of the ground
    truth, so its figure is the largest single-case move across runs: the run with the fewest
    predicted FAILs. A run predicting none moves it the most: one false positive takes that
    run's precision from 1 to 0.
    """
    runs = len(verdict_maps)
    expected_fails = sum(1 for verdict in ground_truth.values() if verdict == EvalVerdict.FAIL)
    return {
        "recall": _one_case_in(expected_fails * runs),
        "precision": _largest_precision_move(verdict_maps, ground_truth),
        "distribution_coverage": _one_case_in(tool_count * len(AuditCategory) * runs),
    }


def _largest_precision_move(verdict_maps: list[VerdictMap], ground_truth: GroundTruth) -> float:
    predicted_fails = [
        sum(
            1
            for cell, verdict in verdicts.items()
            if verdict == EvalVerdict.FAIL and cell in ground_truth
        )
        for verdicts in verdict_maps
    ]
    moves = [_one_case_in(len(verdict_maps) * max(fails, 1)) for fails in predicted_fails]
    return max(moves, default=1.0)


def _one_case_in(support: int) -> float:
    # No single case can move a metric that has no support.
    return 1 / support if support else 1.0


_GATED_METRICS = ("recall", "precision", "distribution_coverage")


class MetricDelta(BaseModel):
    value: float
    resolution: float
    inconclusive: bool


def metric_deltas(
    baseline: EvalMetrics, candidate: EvalMetrics, resolutions: dict[str, float]
) -> dict[str, MetricDelta]:
    deltas: dict[str, MetricDelta] = {}
    for name in _GATED_METRICS:
        value: float = getattr(candidate, name) - getattr(baseline, name)
        resolution = resolutions[name]
        deltas[name] = MetricDelta(
            value=value,
            resolution=resolution,
            inconclusive=abs(value) < resolution and not math.isclose(abs(value), resolution),
        )
    return deltas
