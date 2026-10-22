"""The nuisance aggregation over per-server results: the figure (the mean flagged share), its
Wilson interval and controls, the cutoff-side split, the contrast between sides and the
conclusion check that reads the contrast against zero under every method.

The result value objects live in nuisance_results so the report and the orchestrator share them
without a cycle. The split places each server by its split flaw's disclosure date against the
run's own cutoff, passed in, and counts only the runs flagged through that flaw's counted tools."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date

from evals.holdout_hierarchical import GammaPrior, contrast_hierarchical, hierarchical_interval
from evals.holdout_intervals import (
    Interval,
    agresti_caffo,
    clopper_pearson,
    jeffreys,
    newcombe,
    wilson,
)
from evals.holdout_statistic import (
    ConclusionVerdict,
    Contrast,
    MethodPlacement,
    Side,
    placed,
    side_of,
)
from evals.nuisance_results import NuisanceServerResult

_GAMMA_1_1 = GammaPrior(shape=1.0, scale=1.0)
_GAMMA_2_2 = GammaPrior(shape=2.0, scale=2.0)
_MIN_SIDE = 5  # Newcombe and the conclusion need at least this many servers a side


@dataclass(frozen=True)
class SideStatistic:
    side: Side
    results: tuple[NuisanceServerResult, ...]
    interval: Interval

    @property
    def servers(self) -> int:
        return len(self.results)

    @property
    def split_share_sum(self) -> float:
        return _split_share_sum(self.results)

    @property
    def number(self) -> float:
        return self.split_share_sum / self.servers


def figure(results: Sequence[NuisanceServerResult]) -> float:
    return _share_sum(results) / len(results)


def cited_interval(results: Sequence[NuisanceServerResult]) -> Interval:
    return wilson(_share_sum(results), len(results))


def split_by_side(
    results: Sequence[NuisanceServerResult], run_cutoff: date
) -> dict[Side, SideStatistic]:
    by_side: dict[Side, list[NuisanceServerResult]] = {}
    for result in results:
        if result.split_flaw is None or result.split_disclosure_date is None:
            continue
        side = side_of(result.split_disclosure_date, run_cutoff)
        by_side.setdefault(side, []).append(result)
    return {
        side: SideStatistic(side, tuple(members), wilson(_split_share_sum(members), len(members)))
        for side, members in by_side.items()
    }


def contrast(side_a: SideStatistic, side_b: SideStatistic) -> Contrast | None:
    if side_a.servers < _MIN_SIDE or side_b.servers < _MIN_SIDE:
        return None
    interval = newcombe(
        side_a.split_share_sum, side_a.servers, side_b.split_share_sum, side_b.servers
    )
    return Contrast(side_a.side, side_b.side, interval)


def primary_controls(results: Sequence[NuisanceServerResult], runs: int) -> dict[str, Interval]:
    count = _share_sum(results)
    n = len(results)
    flagged = [result.flagged_runs for result in results]
    return {
        "jeffreys": jeffreys(count, n),
        "clopper_pearson": clopper_pearson(count, n),
        "hierarchical_gamma_1_1": hierarchical_interval(flagged, runs, _GAMMA_1_1),
        "hierarchical_gamma_2_2": hierarchical_interval(flagged, runs, _GAMMA_2_2),
        "incomplete_as_flagged_wilson": wilson(_incomplete_as_flagged_sum(results, runs), n),
    }


def check_conclusion(
    side_a: SideStatistic, side_b: SideStatistic, runs: int
) -> ConclusionVerdict | None:
    if side_a.servers < _MIN_SIDE or side_b.servers < _MIN_SIDE:
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
    split_a, split_b = side_a.split_share_sum, side_b.split_share_sum
    raised_a = _split_incomplete_as_flagged_sum(side_a.results, runs)
    raised_b = _split_incomplete_as_flagged_sum(side_b.results, runs)
    flagged_a = [r.split_flagged_runs for r in side_a.results]
    flagged_b = [r.split_flagged_runs for r in side_b.results]
    raised_runs_a = [r.split_flagged_runs + r.incomplete_unflagged_runs for r in side_a.results]
    raised_runs_b = [r.split_flagged_runs + r.incomplete_unflagged_runs for r in side_b.results]
    n_a, n_b = side_a.servers, side_b.servers
    return [
        placed("newcombe", newcombe(split_a, n_a, split_b, n_b)),
        placed("agresti_caffo", agresti_caffo(split_a, n_a, split_b, n_b)),
        placed(
            "hierarchical_gamma_1_1", contrast_hierarchical(flagged_a, flagged_b, runs, _GAMMA_1_1)
        ),
        placed(
            "hierarchical_gamma_2_2", contrast_hierarchical(flagged_a, flagged_b, runs, _GAMMA_2_2)
        ),
        placed("newcombe_incomplete_as_flagged", newcombe(raised_a, n_a, raised_b, n_b)),
        placed("agresti_caffo_incomplete_as_flagged", agresti_caffo(raised_a, n_a, raised_b, n_b)),
        placed(
            "hierarchical_gamma_1_1_incomplete_as_flagged",
            contrast_hierarchical(raised_runs_a, raised_runs_b, runs, _GAMMA_1_1),
        ),
        placed(
            "hierarchical_gamma_2_2_incomplete_as_flagged",
            contrast_hierarchical(raised_runs_a, raised_runs_b, runs, _GAMMA_2_2),
        ),
    ]


def _share_sum(results: Sequence[NuisanceServerResult]) -> float:
    return sum(result.flagged_share for result in results)


def _split_share_sum(results: Sequence[NuisanceServerResult]) -> float:
    return sum(result.split_flagged_runs / result.runs for result in results)


def _incomplete_as_flagged_sum(results: Sequence[NuisanceServerResult], runs: int) -> float:
    return sum(
        (result.flagged_runs + result.incomplete_unflagged_runs) / runs for result in results
    )


def _split_incomplete_as_flagged_sum(results: Sequence[NuisanceServerResult], runs: int) -> float:
    return sum(
        (result.split_flagged_runs + result.incomplete_unflagged_runs) / runs for result in results
    )
