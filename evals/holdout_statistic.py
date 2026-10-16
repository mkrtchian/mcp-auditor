"""The holdout-specific aggregation over per-target results: the primary number (the mean
detection share), its Wilson interval and controls, the cutoff-side split, the contrast between
sides and the conclusion check that reads the contrast against zero under every method.

The result value objects live in holdout_results so the report and the orchestrator share them
without a cycle. The split recomputes each target's side from its disclosure date against the
run's own cutoff, passed in rather than imported."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from enum import StrEnum

from evals.census_draw import Side, side_of
from evals.holdout_hierarchical import GammaPrior, contrast_hierarchical, hierarchical_interval
from evals.holdout_intervals import (
    Interval,
    agresti_caffo,
    clopper_pearson,
    jeffreys,
    newcombe,
    wilson,
)
from evals.holdout_results import HoldoutTargetResult

_GAMMA_1_1 = GammaPrior(shape=1.0, scale=1.0)
_GAMMA_2_2 = GammaPrior(shape=2.0, scale=2.0)
_MIN_SIDE = 5  # Newcombe and the conclusion need at least this many targets a side


class Placement(StrEnum):
    ABOVE = "above"
    BELOW = "below"
    STRADDLES = "straddles"


@dataclass(frozen=True)
class SideStatistic:
    side: Side
    results: tuple[HoldoutTargetResult, ...]
    interval: Interval

    @property
    def targets(self) -> int:
        return len(self.results)

    @property
    def share_sum(self) -> float:
        return sum(result.detection_share for result in self.results)

    @property
    def number(self) -> float:
        return self.share_sum / self.targets


@dataclass(frozen=True)
class Contrast:
    side_a: Side
    side_b: Side
    interval: Interval


@dataclass(frozen=True)
class MethodPlacement:
    method: str
    interval: Interval
    placement: Placement


@dataclass(frozen=True)
class ConclusionVerdict:
    placement: Placement | None  # the agreed placement, None when the methods disagree
    inconclusive: bool
    cited: MethodPlacement  # Newcombe, the cited method
    disagreeing: tuple[MethodPlacement, ...]


def primary_number(results: Sequence[HoldoutTargetResult]) -> float:
    return sum(result.detection_share for result in results) / len(results)


def cited_interval(results: Sequence[HoldoutTargetResult]) -> Interval:
    return wilson(_share_sum(results), len(results))


def split_by_side(
    results: Sequence[HoldoutTargetResult], run_cutoff: date
) -> dict[Side, SideStatistic]:
    by_side: dict[Side, list[HoldoutTargetResult]] = {}
    for result in results:
        side = side_of(result.disclosure_date, run_cutoff)
        by_side.setdefault(side, []).append(result)
    return {
        side: SideStatistic(side, tuple(members), wilson(_share_sum(members), len(members)))
        for side, members in by_side.items()
    }


def contrast(side_a: SideStatistic, side_b: SideStatistic) -> Contrast | None:
    if side_a.targets < _MIN_SIDE or side_b.targets < _MIN_SIDE:
        return None
    interval = newcombe(side_a.share_sum, side_a.targets, side_b.share_sum, side_b.targets)
    return Contrast(side_a.side, side_b.side, interval)


def primary_controls(results: Sequence[HoldoutTargetResult], runs: int) -> dict[str, Interval]:
    count = _share_sum(results)
    n = len(results)
    detected = [result.detected_runs for result in results]
    unchecked = _unchecked_sum(results, runs)
    return {
        "jeffreys": jeffreys(count, n),
        "clopper_pearson": clopper_pearson(count, n),
        "hierarchical_gamma_1_1": _hierarchical(detected, runs, _GAMMA_1_1),
        "hierarchical_gamma_2_2": _hierarchical(detected, runs, _GAMMA_2_2),
        "unchecked_as_misses_wilson": wilson(unchecked, n),
    }


def check_conclusion(
    side_a: SideStatistic, side_b: SideStatistic, runs: int
) -> ConclusionVerdict | None:
    if side_a.targets < _MIN_SIDE or side_b.targets < _MIN_SIDE:
        return None
    placements = _conclusion_methods(side_a, side_b, runs)
    cited = placements[0]
    disagreeing = tuple(m for m in placements[1:] if m.placement is not cited.placement)
    if disagreeing:
        return ConclusionVerdict(None, True, cited, disagreeing)
    return ConclusionVerdict(cited.placement, False, cited, ())


def _conclusion_methods(
    side_a: SideStatistic, side_b: SideStatistic, runs: int
) -> list[MethodPlacement]:
    checked_a, checked_b = side_a.share_sum, side_b.share_sum
    unchecked_a = _unchecked_sum(side_a.results, runs)
    unchecked_b = _unchecked_sum(side_b.results, runs)
    detected_a = [r.detected_runs for r in side_a.results]
    detected_b = [r.detected_runs for r in side_b.results]
    missed_a = [r.detected_runs_if_unchecked_missed for r in side_a.results]
    missed_b = [r.detected_runs_if_unchecked_missed for r in side_b.results]
    n_a, n_b = side_a.targets, side_b.targets
    return [
        _placed("newcombe", newcombe(checked_a, n_a, checked_b, n_b)),
        _placed("agresti_caffo", agresti_caffo(checked_a, n_a, checked_b, n_b)),
        _placed("hierarchical_gamma_1_1", _hier_contrast(detected_a, detected_b, runs, _GAMMA_1_1)),
        _placed("hierarchical_gamma_2_2", _hier_contrast(detected_a, detected_b, runs, _GAMMA_2_2)),
        _placed("newcombe_unchecked", newcombe(unchecked_a, n_a, unchecked_b, n_b)),
        _placed("agresti_caffo_unchecked", agresti_caffo(unchecked_a, n_a, unchecked_b, n_b)),
        _placed(
            "hierarchical_gamma_1_1_unchecked",
            _hier_contrast(missed_a, missed_b, runs, _GAMMA_1_1),
        ),
        _placed(
            "hierarchical_gamma_2_2_unchecked",
            _hier_contrast(missed_a, missed_b, runs, _GAMMA_2_2),
        ),
    ]


def _placed(method: str, interval: Interval) -> MethodPlacement:
    return MethodPlacement(method, interval, _placement(interval))


def _placement(interval: Interval) -> Placement:
    if interval.low > 0:
        return Placement.ABOVE
    if interval.high < 0:
        return Placement.BELOW
    return Placement.STRADDLES


def _hierarchical(detected: list[int], runs: int, prior: GammaPrior) -> Interval:
    return hierarchical_interval(detected, runs, prior)


def _hier_contrast(a: list[int], b: list[int], runs: int, prior: GammaPrior) -> Interval:
    return contrast_hierarchical(a, b, runs, prior)


def _share_sum(results: Sequence[HoldoutTargetResult]) -> float:
    return sum(result.detection_share for result in results)


def _unchecked_sum(results: Sequence[HoldoutTargetResult], runs: int) -> float:
    return sum(result.detected_runs_if_unchecked_missed / runs for result in results)
