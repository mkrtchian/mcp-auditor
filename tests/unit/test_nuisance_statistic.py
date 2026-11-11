"""The nuisance aggregation over per-server results: the figure, the cutoff-side split on the
split flaw, the contrast and the conclusion check. Reference values are the direct interval calls
on the crafted counts; nothing is fetched."""

import math
from datetime import date

from evals.cve.holdout_hierarchical import GammaPrior, hierarchical_interval
from evals.cve.holdout_intervals import clopper_pearson, jeffreys, newcombe, wilson
from evals.cve.holdout_statistic import Placement, Side
from evals.nuisance_statistic import (
    check_conclusion,
    cited_interval,
    contrast,
    figure,
    incomplete_as_flagged,
    observed,
    primary_controls,
    split_by_side,
)
from tests.unit.support.test_nuisance_statistic_given import RUN_CUTOFF, a_server_result, sides_of

RUNS = 3


def test_figure_is_the_mean_flagged_share():
    results = [
        a_server_result("A", flagged_runs=3),
        a_server_result("B", flagged_runs=1),
        a_server_result("C", flagged_runs=0),
    ]
    assert math.isclose(figure(results), 4 / 9)


def test_cited_interval_is_wilson_on_the_sum_of_flagged_shares():
    results = [
        a_server_result("A", flagged_runs=3),
        a_server_result("B", flagged_runs=1),
        a_server_result("C", flagged_runs=0),
    ]
    assert cited_interval(results) == wilson(4 / 3, 3)


def test_split_by_side_places_each_server_by_its_split_flaw_date():
    on_cutoff = a_server_result("ON", split_disclosure_date=RUN_CUTOFF)
    day_after = a_server_result("AFTER", split_disclosure_date=date(2026, 5, 19))
    outside = a_server_result("OUT", split_flaw=None, split_disclosure_date=None)
    split = split_by_side([on_cutoff, day_after, outside], RUN_CUTOFF)
    assert [r.server_package for r in split[Side.PRE_CUTOFF].results] == ["ON"]
    assert [r.server_package for r in split[Side.POST_CUTOFF].results] == ["AFTER"]
    assert split[Side.PRE_CUTOFF].servers == 1
    assert split[Side.POST_CUTOFF].servers == 1


def test_split_share_sum_counts_only_the_runs_flagged_through_the_split_flaw():
    elsewhere = a_server_result("A", flagged_runs=3, split_flagged_runs=0)
    through_split = a_server_result("B", flagged_runs=3, split_flagged_runs=2)
    side = split_by_side([elsewhere, through_split], RUN_CUTOFF)[Side.PRE_CUTOFF]
    assert math.isclose(side.split_share_sum, 2 / 3)
    assert math.isclose(side.number, (2 / 3) / 2)
    assert side.interval == wilson(2 / 3, 2)


def test_contrast_is_none_below_five_servers_a_side():
    pre, post = sides_of(4, pre_flagged=3)
    assert contrast(pre, post) is None


def test_contrast_is_the_newcombe_interval_over_the_split_sums_at_five_a_side():
    pre, post = sides_of(5, pre_flagged=3, post_flagged=1)
    result = contrast(pre, post)
    assert result is not None
    assert math.isclose(pre.split_share_sum, 5.0)
    assert math.isclose(post.split_share_sum, 5 / 3)
    assert result.interval == newcombe(pre.split_share_sum, 5, post.split_share_sum, 5)


def test_check_conclusion_is_none_below_five_servers_a_side():
    pre, post = sides_of(4, pre_flagged=3)
    assert check_conclusion(pre, post, RUNS) is None


def test_check_conclusion_is_inconclusive_when_counting_incomplete_runs_as_flagged_moves_the_gap():
    pre, post = sides_of(5, pre_flagged=3, post_incomplete_unflagged=3)

    verdict = check_conclusion(pre, post, RUNS)

    assert verdict is not None
    assert (verdict.cited.method, verdict.cited.placement) == ("newcombe", Placement.ABOVE)
    assert verdict.inconclusive
    assert [method.method for method in verdict.disagreeing] == [
        "newcombe_incomplete_as_flagged",
        "agresti_caffo_incomplete_as_flagged",
        "hierarchical_gamma_1_1_incomplete_as_flagged",
        "hierarchical_gamma_2_2_incomplete_as_flagged",
    ]


def test_observed_reads_only_the_runs_flagged_through_the_split_flaw():
    pre, _ = sides_of(5, pre_flagged=3)
    elsewhere = a_server_result("A", flagged_runs=3, split_flagged_runs=1)
    side = split_by_side([elsewhere, *pre.results], RUN_CUTOFF)[Side.PRE_CUTOFF]
    reading = observed(side)
    assert reading.share_sum == side.split_share_sum
    assert reading.counted_runs == (1, 3, 3, 3, 3, 3)


def test_incomplete_as_flagged_adds_the_incomplete_unflagged_runs_to_the_split_flagged_ones():
    _, post = sides_of(5, pre_flagged=3, post_flagged=1, post_incomplete_unflagged=2)
    reading = incomplete_as_flagged(post, RUNS)
    assert math.isclose(reading.share_sum, 5 * (1 + 2) / RUNS)
    assert reading.counted_runs == (3,) * 5


def test_primary_controls_are_the_five_intervals_on_the_flagged_shares():
    results = [a_server_result("A", flagged_runs=3), a_server_result("B", flagged_runs=1)]
    assert primary_controls(results, RUNS) == {
        "jeffreys": jeffreys(4 / 3, 2),
        "clopper_pearson": clopper_pearson(4 / 3, 2),
        "hierarchical_gamma_1_1": hierarchical_interval([3, 1], RUNS, GammaPrior(1.0, 1.0)),
        "hierarchical_gamma_2_2": hierarchical_interval([3, 1], RUNS, GammaPrior(2.0, 2.0)),
        "incomplete_as_flagged_wilson": wilson(4 / 3, 2),
    }


def test_incomplete_as_flagged_control_counts_the_incomplete_unflagged_runs_as_flagged():
    results = [a_server_result("A", flagged_runs=0, incomplete_unflagged_runs=2)]
    bound = primary_controls(results, RUNS)["incomplete_as_flagged_wilson"]
    assert bound == wilson(2 / 3, 1)
    assert bound != cited_interval(results)
