import math
from dataclasses import dataclass

from pydantic import BaseModel

from evals.gate import Observation
from evals.ground_truth import GroundTruth
from evals.metrics import HoneypotMetrics, VerdictMap
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

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


def floor_breaches(metrics: HoneypotMetrics, count: DetectionCount) -> list[str]:
    recall = ["recall"] if recall_floor_breached(count) else []
    return recall + [name for name, floor in FLOORS.items() if getattr(metrics, name) < floor]


def recall_floor_breached(count: DetectionCount) -> bool:
    """One planted flaw found per run, on average (ADR 022): the collapse it catches, a judge
    that passes everything, finds none. A count, not a mean, so that no rounding decides it.
    A ground truth with no FAIL cell always breaches it: there is no flaw to find.
    """
    return count.detections < count.runs


def recall_breach_reason(count: DetectionCount) -> str:
    return f"recall: {count.detections} detection(s) over {count.runs} runs, under one per run"


def floor_breach_reason(name: str, value: float) -> str:
    return f"{name} {value:.2f} under its floor {FLOORS[name]:.2f}"


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


class MetricDelta(BaseModel):
    value: float
    resolution: float
    inconclusive: bool


def metric_deltas(
    baseline: HoneypotMetrics, candidate: HoneypotMetrics, resolutions: dict[str, float]
) -> dict[str, MetricDelta]:
    deltas: dict[str, MetricDelta] = {}
    for name, resolution in resolutions.items():
        value: float = getattr(candidate, name) - getattr(baseline, name)
        deltas[name] = MetricDelta(
            value=value,
            resolution=resolution,
            inconclusive=abs(value) < resolution and not math.isclose(abs(value), resolution),
        )
    return deltas
