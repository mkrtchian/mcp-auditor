"""The detection aggregation over per-target results: the holdout detection rate (the mean
detection share), its Wilson interval and controls, the cutoff-side split and the conclusion
check that reads the contrast against zero under every method.

The result value objects live in holdout_results so the report and the orchestrator share them
without a cycle. The split recomputes each target's side from its disclosure date against the
run's own cutoff, passed in."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date

from evals.cve.detection.holdout_results import HoldoutTargetResult
from evals.cve.holdout_hierarchical import DEFAULT_GRID, Grid
from evals.cve.holdout_intervals import Interval, wilson
from evals.cve.holdout_statistic import (
    MIN_SIDE,
    Conclusion,
    Reading,
    Side,
    conclude,
    rate_controls,
    read_contrast,
    side_of,
)


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


def detection_rate_controls(
    results: Sequence[HoldoutTargetResult], runs: int, *, grid: Grid = DEFAULT_GRID
) -> dict[str, Interval]:
    reading = Reading(_share_sum(results), tuple(r.detected_runs for r in results))
    return {
        **rate_controls(reading, runs, grid),
        "unchecked_as_misses_wilson": wilson(_unchecked_sum(results, runs), reading.members),
    }


def check_conclusion(
    side_a: SideStatistic, side_b: SideStatistic, runs: int, *, grid: Grid = DEFAULT_GRID
) -> Conclusion | None:
    if side_a.targets < MIN_SIDE or side_b.targets < MIN_SIDE:
        return None
    cited, *others = [
        *read_contrast(observed(side_a), observed(side_b), runs, grid=grid),
        *read_contrast(
            unchecked_as_misses(side_a, runs),
            unchecked_as_misses(side_b, runs),
            runs,
            "_unchecked",
            grid=grid,
        ),
    ]
    return conclude(cited, others)


def observed(side: SideStatistic) -> Reading:
    return Reading(side.share_sum, tuple(r.detected_runs for r in side.results))


def unchecked_as_misses(side: SideStatistic, runs: int) -> Reading:
    return Reading(
        _unchecked_sum(side.results, runs),
        tuple(r.detected_runs_if_unchecked_missed for r in side.results),
    )


def _share_sum(results: Sequence[HoldoutTargetResult]) -> float:
    return sum(result.detection_share for result in results)


def _unchecked_sum(results: Sequence[HoldoutTargetResult], runs: int) -> float:
    return sum(result.detected_runs_if_unchecked_missed / runs for result in results)
