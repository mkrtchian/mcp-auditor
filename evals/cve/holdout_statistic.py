"""What both holdout rates share: the cutoff sides, the readings of a side or a run, the rate
controls, the four contrast methods and the conclusion rule that reads the contrast against zero
under every method. Each suite aggregates its own results into these readings, the detection
suite in detection/statistic and the nuisance suite in nuisance/statistic."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from enum import StrEnum

from evals.cve.holdout_hierarchical import (
    DEFAULT_GRID,
    GammaPrior,
    Grid,
    contrast_hierarchical,
    hierarchical_interval,
)
from evals.cve.holdout_intervals import (
    Interval,
    agresti_caffo,
    clopper_pearson,
    jeffreys,
    newcombe,
)

_GAMMA_1_1 = GammaPrior(shape=1.0, scale=1.0)
_GAMMA_2_2 = GammaPrior(shape=2.0, scale=2.0)
MIN_SIDE = 5  # Newcombe and the conclusion need at least this many members a side


class Side(StrEnum):
    PRE_CUTOFF = "pre_cutoff"
    POST_CUTOFF = "post_cutoff"


class Placement(StrEnum):
    ABOVE = "above"
    BELOW = "below"
    STRADDLES = "straddles"


@dataclass(frozen=True)
class MethodPlacement:
    method: str
    interval: Interval
    placement: Placement


@dataclass(frozen=True)
class Reading:
    """One way of counting members, a side or a whole run: the sum of their shares, and the runs
    counted per member."""

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


def side_of(disclosure_date: date, cutoff: date) -> Side:
    return Side.PRE_CUTOFF if disclosure_date <= cutoff else Side.POST_CUTOFF


def rate_controls(reading: Reading, runs: int, grid: Grid) -> dict[str, Interval]:
    count, n, member_runs = reading.share_sum, reading.members, reading.counted_runs
    return {
        "jeffreys": jeffreys(count, n),
        "clopper_pearson": clopper_pearson(count, n),
        "hierarchical_gamma_1_1": hierarchical_interval(member_runs, runs, _GAMMA_1_1, grid),
        "hierarchical_gamma_2_2": hierarchical_interval(member_runs, runs, _GAMMA_2_2, grid),
    }


def conclude(cited: MethodPlacement, others: Sequence[MethodPlacement]) -> Conclusion:
    disagreeing = tuple(m for m in others if m.placement is not cited.placement)
    if disagreeing:
        return Conclusion(None, True, cited, disagreeing)
    return Conclusion(cited.placement, False, cited, ())


def read_contrast(
    reading_a: Reading,
    reading_b: Reading,
    runs: int,
    suffix: str = "",
    *,
    grid: Grid = DEFAULT_GRID,
) -> list[MethodPlacement]:
    """Newcombe, Agresti-Caffo and the two hierarchical contrasts, in that order, each named
    with the suffix appended."""
    counts = (reading_a.share_sum, reading_a.members, reading_b.share_sum, reading_b.members)
    a, b = reading_a.counted_runs, reading_b.counted_runs
    return [
        placed(f"newcombe{suffix}", newcombe(*counts)),
        placed(f"agresti_caffo{suffix}", agresti_caffo(*counts)),
        placed(
            f"hierarchical_gamma_1_1{suffix}", contrast_hierarchical(a, b, runs, _GAMMA_1_1, grid)
        ),
        placed(
            f"hierarchical_gamma_2_2{suffix}", contrast_hierarchical(a, b, runs, _GAMMA_2_2, grid)
        ),
    ]


def placed(method: str, interval: Interval) -> MethodPlacement:
    return MethodPlacement(method, interval, placement_of(interval))


def placement_of(interval: Interval) -> Placement:
    if interval.low > 0:
        return Placement.ABOVE
    if interval.high < 0:
        return Placement.BELOW
    return Placement.STRADDLES
