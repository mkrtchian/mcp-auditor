"""The holdout-specific aggregation over per-target results: the holdout detection rate (the mean
detection share), its Wilson interval and controls, the cutoff-side split, the contrast between
sides and the conclusion check that reads the contrast against zero under every method.

The result value objects live in holdout_results so the report and the orchestrator share them
without a cycle. The split recomputes each target's side from its disclosure date against the
run's own cutoff, passed in."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from enum import StrEnum

from evals.cve.detection.holdout_results import HoldoutTargetResult
from evals.cve.holdout_hierarchical import GammaPrior, contrast_hierarchical, hierarchical_interval
from evals.cve.holdout_intervals import (
    Interval,
    agresti_caffo,
    clopper_pearson,
    jeffreys,
    newcombe,
    wilson,
)

_GAMMA_1_1 = GammaPrior(shape=1.0, scale=1.0)
_GAMMA_2_2 = GammaPrior(shape=2.0, scale=2.0)
_MIN_SIDE = 5  # Newcombe and the conclusion need at least this many targets a side


class Side(StrEnum):
    PRE_CUTOFF = "pre_cutoff"
    POST_CUTOFF = "post_cutoff"


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
class Reading:
    """One way of counting a side: the sum of its shares, and the runs counted per member."""

    share_sum: float
    counted_runs: tuple[int, ...]

    @property
    def members(self) -> int:
        return len(self.counted_runs)


@dataclass(frozen=True)
class Conclusion:
    placement: Placement | None  # the agreed placement, None when the methods disagree
    inconclusive: bool
    cited: MethodPlacement  # Newcombe, the cited method
    disagreeing: tuple[MethodPlacement, ...]


def holdout_detection_rate(results: Sequence[HoldoutTargetResult]) -> float:
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


def side_of(disclosure_date: date, cutoff: date) -> Side:
    return Side.PRE_CUTOFF if disclosure_date <= cutoff else Side.POST_CUTOFF


def contrast(side_a: SideStatistic, side_b: SideStatistic) -> Contrast | None:
    if side_a.targets < _MIN_SIDE or side_b.targets < _MIN_SIDE:
        return None
    interval = newcombe(side_a.share_sum, side_a.targets, side_b.share_sum, side_b.targets)
    return Contrast(side_a.side, side_b.side, interval)


def detection_rate_controls(
    results: Sequence[HoldoutTargetResult], runs: int
) -> dict[str, Interval]:
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


def check_conclusion(side_a: SideStatistic, side_b: SideStatistic, runs: int) -> Conclusion | None:
    if side_a.targets < _MIN_SIDE or side_b.targets < _MIN_SIDE:
        return None
    cited, *others = [
        *read_contrast(observed(side_a), observed(side_b), runs),
        *read_contrast(
            unchecked_as_misses(side_a, runs), unchecked_as_misses(side_b, runs), runs, "_unchecked"
        ),
    ]
    return conclude(cited, others)


def conclude(cited: MethodPlacement, others: Sequence[MethodPlacement]) -> Conclusion:
    disagreeing = tuple(m for m in others if m.placement is not cited.placement)
    if disagreeing:
        return Conclusion(None, True, cited, disagreeing)
    return Conclusion(cited.placement, False, cited, ())


def read_contrast(
    reading_a: Reading, reading_b: Reading, runs: int, suffix: str = ""
) -> list[MethodPlacement]:
    """Newcombe, Agresti-Caffo and the two hierarchical contrasts, in that order, each named
    with the suffix appended."""
    counts = (reading_a.share_sum, reading_a.members, reading_b.share_sum, reading_b.members)
    a, b = reading_a.counted_runs, reading_b.counted_runs
    return [
        placed(f"newcombe{suffix}", newcombe(*counts)),
        placed(f"agresti_caffo{suffix}", agresti_caffo(*counts)),
        placed(f"hierarchical_gamma_1_1{suffix}", contrast_hierarchical(a, b, runs, _GAMMA_1_1)),
        placed(f"hierarchical_gamma_2_2{suffix}", contrast_hierarchical(a, b, runs, _GAMMA_2_2)),
    ]


def observed(side: SideStatistic) -> Reading:
    return Reading(side.share_sum, tuple(r.detected_runs for r in side.results))


def unchecked_as_misses(side: SideStatistic, runs: int) -> Reading:
    return Reading(
        _unchecked_sum(side.results, runs),
        tuple(r.detected_runs_if_unchecked_missed for r in side.results),
    )


def placed(method: str, interval: Interval) -> MethodPlacement:
    return MethodPlacement(method, interval, placement_of(interval))


def placement_of(interval: Interval) -> Placement:
    if interval.low > 0:
        return Placement.ABOVE
    if interval.high < 0:
        return Placement.BELOW
    return Placement.STRADDLES


def _hierarchical(detected: list[int], runs: int, prior: GammaPrior) -> Interval:
    return hierarchical_interval(detected, runs, prior)


def _share_sum(results: Sequence[HoldoutTargetResult]) -> float:
    return sum(result.detection_share for result in results)


def _unchecked_sum(results: Sequence[HoldoutTargetResult], runs: int) -> float:
    return sum(result.detected_runs_if_unchecked_missed / runs for result in results)
