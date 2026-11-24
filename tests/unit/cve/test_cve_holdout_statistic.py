"""What both holdout rates share: the cutoff side, the contrast readings and the conclusion rule.
Reference values are the direct interval calls on the crafted counts; nothing is fetched."""

from datetime import date

from evals.cve.holdout_hierarchical import GammaPrior, contrast_hierarchical
from evals.cve.holdout_intervals import Interval
from evals.cve.holdout_statistic import (
    Conclusion,
    Placement,
    Reading,
    Side,
    conclude,
    placed,
    read_contrast,
    side_of,
)
from tests.unit.support.coarse_grid import COARSE_GRID

RUN_CUTOFF = date(2026, 5, 18)
RUNS = 3


def test_side_of_counts_the_cutoff_day_itself_as_pre_cutoff():
    assert side_of(RUN_CUTOFF, RUN_CUTOFF) == Side.PRE_CUTOFF
    assert side_of(RUN_CUTOFF.replace(day=17), RUN_CUTOFF) == Side.PRE_CUTOFF
    assert side_of(RUN_CUTOFF.replace(day=19), RUN_CUTOFF) == Side.POST_CUTOFF


ABOVE_ZERO = Interval(0.10, 0.60)
BELOW_ZERO = Interval(-0.60, -0.10)
ACROSS_ZERO = Interval(-0.20, 0.30)


def test_conclude_carries_the_placement_every_method_agrees_on_above_zero():
    cited = placed("newcombe", ABOVE_ZERO)
    others = [placed("agresti_caffo", ABOVE_ZERO), placed("hierarchical", Interval(0.05, 0.70))]
    assert conclude(cited, others) == Conclusion(Placement.ABOVE, False, cited, ())


def test_conclude_carries_an_agreed_placement_below_zero_or_across_it():
    below = placed("newcombe", BELOW_ZERO)
    across = placed("newcombe", ACROSS_ZERO)
    assert conclude(below, [placed("agresti_caffo", BELOW_ZERO)]).placement is Placement.BELOW
    assert conclude(across, [placed("agresti_caffo", ACROSS_ZERO)]).placement is Placement.STRADDLES


def test_conclude_is_inconclusive_when_one_other_method_moves_the_placement():
    cited = placed("newcombe", ABOVE_ZERO)
    moved = placed("newcombe_unchecked", ACROSS_ZERO)
    conclusion = conclude(cited, [placed("agresti_caffo", ABOVE_ZERO), moved])
    assert conclusion == Conclusion(None, True, cited, (moved,))


def test_conclude_lists_every_disagreeing_method_in_input_order_and_no_agreeing_one():
    cited = placed("newcombe", ABOVE_ZERO)
    first = placed("agresti_caffo", BELOW_ZERO)
    second = placed("hierarchical", ACROSS_ZERO)
    conclusion = conclude(cited, [first, placed("agreeing", ABOVE_ZERO), second])
    assert conclusion.disagreeing == (first, second)


def test_conclude_lets_the_cited_placement_stand_without_other_methods():
    cited = placed("newcombe", BELOW_ZERO)
    assert conclude(cited, []) == Conclusion(Placement.BELOW, False, cited, ())


def test_read_contrast_places_a_lopsided_gap_above_zero_under_the_four_suffixed_methods():
    placements = read_contrast(
        Reading(5.0, (3,) * 5), Reading(0.0, (0,) * 5), RUNS, "_suffix", grid=COARSE_GRID
    )
    assert [placement.method for placement in placements] == [
        "newcombe_suffix",
        "agresti_caffo_suffix",
        "hierarchical_gamma_1_1_suffix",
        "hierarchical_gamma_2_2_suffix",
    ]
    assert all(placement.placement is Placement.ABOVE for placement in placements)


def test_read_contrast_computes_the_hierarchical_contrasts_on_the_grid_it_is_given():
    coarse = read_contrast(Reading(5.0, (3,) * 5), Reading(0.0, (0,) * 5), RUNS, grid=COARSE_GRID)
    expected = contrast_hierarchical((3,) * 5, (0,) * 5, RUNS, GammaPrior(1.0, 1.0), COARSE_GRID)
    assert coarse[2].interval == expected
