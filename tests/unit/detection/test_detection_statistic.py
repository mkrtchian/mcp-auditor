"""The detection aggregation over per-target results: the holdout detection rate, the cutoff-side
split, the contrast and the conclusion check. Reference values are the direct interval calls on
the crafted counts; nothing is fetched."""

import math
from datetime import date

from evals.cve.detection.statistic import (
    check_conclusion,
    cited_interval,
    detection_rate_controls,
    holdout_detection_rate,
    observed,
    split_by_side,
    unchecked_as_misses,
)
from evals.cve.holdout_hierarchical import GammaPrior, hierarchical_interval
from evals.cve.holdout_intervals import clopper_pearson, jeffreys, newcombe, wilson
from evals.cve.holdout_statistic import Side
from tests.unit.detection.support.holdout_report_runs import RUNS, a_target_result
from tests.unit.support.coarse_grid import COARSE_GRID

RUN_CUTOFF = date(2026, 5, 18)


def test_the_holdout_detection_rate_is_the_sum_of_shares_over_the_target_count():
    results = [
        a_target_result("A", detected_runs=3),  # share 1.0
        a_target_result("B", detected_runs=1),  # share 1/3
        a_target_result("C", detected_runs=0),  # share 0.0
    ]
    expected = (3 / 3 + 1 / 3 + 0 / 3) / 3
    assert math.isclose(holdout_detection_rate(results), expected)
    assert math.isclose(
        holdout_detection_rate(results), sum(r.detection_share for r in results) / 3
    )


def test_cited_interval_is_wilson_on_the_sum_of_shares():
    results = [a_target_result("A", detected_runs=3), a_target_result("B", detected_runs=1)]
    share_sum = 3 / 3 + 1 / 3
    assert cited_interval(results) == wilson(share_sum, 2)


def test_split_by_side_recomputes_the_side_from_the_disclosure_date():
    pre_by_date = a_target_result("PRE", disclosure_date=date(2026, 1, 1), detected_runs=3)
    post_by_date = a_target_result("POST", disclosure_date=date(2026, 12, 1), detected_runs=0)
    split = split_by_side([pre_by_date, post_by_date], RUN_CUTOFF)
    assert [r.flaw_id for r in split[Side.PRE_CUTOFF].results] == ["PRE"]
    assert [r.flaw_id for r in split[Side.POST_CUTOFF].results] == ["POST"]


def test_split_numbers_and_interval_are_wilson_per_side():
    results = [a_target_result("A", detected_runs=3), a_target_result("B", detected_runs=0)]
    side = split_by_side(results, RUN_CUTOFF)[Side.PRE_CUTOFF]
    assert side.targets == 2
    assert math.isclose(side.number, (1.0 + 0.0) / 2)
    assert side.interval == wilson(1.0, 2)


def test_check_conclusion_cites_the_newcombe_interval_of_the_observed_shares():
    pre, post = _split_sides(5, 5, detected_runs=3)
    conclusion = check_conclusion(pre, post, RUNS, grid=COARSE_GRID)
    assert conclusion is not None
    assert conclusion.cited.interval == newcombe(pre.share_sum, 5, post.share_sum, 5)


def _split_sides(pre: int, post: int, detected_runs: int):
    results = [
        a_target_result(f"PRE{i}", disclosure_date=date(2026, 1, 1), detected_runs=detected_runs)
        for i in range(pre)
    ] + [
        a_target_result(f"POST{i}", disclosure_date=date(2026, 12, 1), detected_runs=detected_runs)
        for i in range(post)
    ]
    split = split_by_side(results, RUN_CUTOFF)
    return split[Side.PRE_CUTOFF], split[Side.POST_CUTOFF]


def test_check_conclusion_is_none_below_five_targets_a_side():
    pre, post = _split_sides(4, 4, detected_runs=3)
    assert check_conclusion(pre, post, RUNS, grid=COARSE_GRID) is None


def test_check_conclusion_is_inconclusive_when_counting_unchecked_runs_as_misses_moves_the_gap():
    pre = [
        a_target_result(
            f"PRE{i}",
            disclosure_date=date(2026, 1, 1),
            detected_runs=3,
            detected_runs_if_unchecked_missed=0,
        )
        for i in range(5)
    ]
    post = [
        a_target_result(f"POST{i}", disclosure_date=date(2026, 12, 1), detected_runs=0)
        for i in range(5)
    ]
    split = split_by_side(pre + post, RUN_CUTOFF)

    conclusion = check_conclusion(
        split[Side.PRE_CUTOFF], split[Side.POST_CUTOFF], RUNS, grid=COARSE_GRID
    )

    assert conclusion is not None
    assert conclusion.cited.method == "newcombe"
    assert conclusion.inconclusive
    assert [method.method for method in conclusion.disagreeing] == [
        "newcombe_unchecked",
        "agresti_caffo_unchecked",
        "hierarchical_gamma_1_1_unchecked",
        "hierarchical_gamma_2_2_unchecked",
    ]


def test_observed_reads_the_share_sum_and_the_detected_runs_per_target():
    results = [
        a_target_result("A", detected_runs=3, detected_runs_if_unchecked_missed=1),
        a_target_result("B", detected_runs=1, detected_runs_if_unchecked_missed=0),
    ]
    side = split_by_side(results, RUN_CUTOFF)[Side.PRE_CUTOFF]

    reading = observed(side)

    assert math.isclose(reading.share_sum, 4 / RUNS)
    assert reading.counted_runs == (3, 1)
    assert reading.members == 2


def test_unchecked_as_misses_reads_the_runs_detected_with_every_unchecked_run_missed():
    results = [
        a_target_result("A", detected_runs=3, detected_runs_if_unchecked_missed=1),
        a_target_result("B", detected_runs=1, detected_runs_if_unchecked_missed=0),
    ]
    side = split_by_side(results, RUN_CUTOFF)[Side.PRE_CUTOFF]
    reading = unchecked_as_misses(side, RUNS)
    assert math.isclose(reading.share_sum, 1 / RUNS)
    assert reading.counted_runs == (1, 0)


def test_the_detection_rate_controls_are_the_five_intervals_on_the_detection_shares():
    results = [
        a_target_result("A", detected_runs=3, detected_runs_if_unchecked_missed=2),
        a_target_result("B", detected_runs=1, detected_runs_if_unchecked_missed=1),
    ]
    assert detection_rate_controls(results, RUNS, grid=COARSE_GRID) == {
        "jeffreys": jeffreys(4 / 3, 2),
        "clopper_pearson": clopper_pearson(4 / 3, 2),
        "hierarchical_gamma_1_1": hierarchical_interval(
            [3, 1], RUNS, GammaPrior(1.0, 1.0), COARSE_GRID
        ),
        "hierarchical_gamma_2_2": hierarchical_interval(
            [3, 1], RUNS, GammaPrior(2.0, 2.0), COARSE_GRID
        ),
        "unchecked_as_misses_wilson": wilson(3 / 3, 2),
    }


def test_unchecked_as_misses_control_is_wilson_on_the_recomputed_count():
    results = [
        a_target_result("A", detected_runs=3, detected_runs_if_unchecked_missed=1),
        a_target_result("B", detected_runs=2, detected_runs_if_unchecked_missed=0),
    ]
    recomputed = 1 / RUNS + 0 / RUNS
    controls = detection_rate_controls(results, RUNS, grid=COARSE_GRID)
    assert controls["unchecked_as_misses_wilson"] == wilson(recomputed, 2)
