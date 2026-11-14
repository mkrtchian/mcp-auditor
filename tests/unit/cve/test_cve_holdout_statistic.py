"""The holdout aggregation over per-target results: the holdout detection rate, the cutoff-side
split, the contrast and the conclusion check. Reference values are the direct interval calls on
the crafted counts; nothing is fetched."""

import math
from datetime import date

from evals.cve.detection.holdout_results import HoldoutRunStatus, HoldoutTargetResult
from evals.cve.holdout_hierarchical import GammaPrior, hierarchical_interval
from evals.cve.holdout_intervals import Interval, clopper_pearson, jeffreys, newcombe, wilson
from evals.cve.holdout_statistic import (
    Conclusion,
    Placement,
    Reading,
    Side,
    check_conclusion,
    cited_interval,
    conclude,
    contrast,
    detection_rate_controls,
    holdout_detection_rate,
    observed,
    placed,
    read_contrast,
    side_of,
    split_by_side,
    unchecked_as_misses,
)

RUN_CUTOFF = date(2026, 5, 18)
RUNS = 3


def _result(
    flaw_id: str = "CVE-0000-0000",
    *,
    disclosure_date: date = date(2026, 1, 1),
    detected_runs: int = 0,
    detected_runs_if_unchecked_missed: int = 0,
    runs: int = RUNS,
) -> HoldoutTargetResult:
    return HoldoutTargetResult(
        flaw_id=flaw_id,
        disclosure_date=disclosure_date,
        class_labels=("read_outside_scope",),
        tools_count=4,
        ran_in_fallback=False,
        statuses=tuple(
            HoldoutRunStatus(
                detected=index < detected_runs,
                detected_if_unchecked_missed=index < detected_runs_if_unchecked_missed,
                surfaced_places=[],
                struck_places=[],
                unchecked_places=[],
                aimed=index < detected_runs,
                fail_without_proof=False,
                incomplete=False,
                non_protocol_lines=0,
                lost_connection_responses=0,
                unchecked_reason=None,
                replay_attempt_failures=[],
                missed_call_causes=[],
            )
            for index in range(runs)
        ),
        run_cost=0.01,
    )


def test_the_holdout_detection_rate_is_the_sum_of_shares_over_the_target_count():
    results = [
        _result("A", detected_runs=3),  # share 1.0
        _result("B", detected_runs=1),  # share 1/3
        _result("C", detected_runs=0),  # share 0.0
    ]
    expected = (3 / 3 + 1 / 3 + 0 / 3) / 3
    assert math.isclose(holdout_detection_rate(results), expected)
    assert math.isclose(
        holdout_detection_rate(results), sum(r.detection_share for r in results) / 3
    )


def test_cited_interval_is_wilson_on_the_sum_of_shares():
    results = [_result("A", detected_runs=3), _result("B", detected_runs=1)]
    share_sum = 3 / 3 + 1 / 3
    assert cited_interval(results) == wilson(share_sum, 2)


def test_side_of_counts_the_cutoff_day_itself_as_pre_cutoff():
    assert side_of(RUN_CUTOFF, RUN_CUTOFF) == Side.PRE_CUTOFF
    assert side_of(RUN_CUTOFF.replace(day=17), RUN_CUTOFF) == Side.PRE_CUTOFF
    assert side_of(RUN_CUTOFF.replace(day=19), RUN_CUTOFF) == Side.POST_CUTOFF


def test_split_by_side_recomputes_the_side_from_the_disclosure_date():
    pre_by_date = _result("PRE", disclosure_date=date(2026, 1, 1), detected_runs=3)
    post_by_date = _result("POST", disclosure_date=date(2026, 12, 1), detected_runs=0)
    split = split_by_side([pre_by_date, post_by_date], RUN_CUTOFF)
    assert [r.flaw_id for r in split[Side.PRE_CUTOFF].results] == ["PRE"]
    assert [r.flaw_id for r in split[Side.POST_CUTOFF].results] == ["POST"]


def test_split_numbers_and_interval_are_wilson_per_side():
    results = [_result("A", detected_runs=3), _result("B", detected_runs=0)]
    side = split_by_side(results, RUN_CUTOFF)[Side.PRE_CUTOFF]
    assert side.targets == 2
    assert math.isclose(side.number, (1.0 + 0.0) / 2)
    assert side.interval == wilson(1.0, 2)


def _split_sides(pre: int, post: int, detected_runs: int):
    results = [
        _result(f"PRE{i}", disclosure_date=date(2026, 1, 1), detected_runs=detected_runs)
        for i in range(pre)
    ] + [
        _result(f"POST{i}", disclosure_date=date(2026, 12, 1), detected_runs=detected_runs)
        for i in range(post)
    ]
    split = split_by_side(results, RUN_CUTOFF)
    return split[Side.PRE_CUTOFF], split[Side.POST_CUTOFF]


def test_contrast_is_none_below_five_targets_a_side():
    pre, post = _split_sides(4, 4, detected_runs=3)
    assert contrast(pre, post) is None


def test_contrast_is_the_newcombe_interval_at_five_targets_a_side():
    pre, post = _split_sides(5, 5, detected_runs=3)
    result = contrast(pre, post)
    assert result is not None
    assert result.interval == newcombe(pre.share_sum, 5, post.share_sum, 5)


def test_check_conclusion_is_none_below_five_targets_a_side():
    pre, post = _split_sides(4, 4, detected_runs=3)
    assert check_conclusion(pre, post, RUNS) is None


def test_check_conclusion_is_inconclusive_when_counting_unchecked_runs_as_misses_moves_the_gap():
    pre = [_result(f"PRE{i}", disclosure_date=date(2026, 1, 1), detected_runs=3) for i in range(5)]
    post = [_result(f"POST{i}", disclosure_date=date(2026, 12, 1)) for i in range(5)]
    split = split_by_side(pre + post, RUN_CUTOFF)

    verdict = check_conclusion(split[Side.PRE_CUTOFF], split[Side.POST_CUTOFF], RUNS)

    assert verdict is not None
    assert verdict.cited.method == "newcombe"
    assert verdict.inconclusive
    assert [method.method for method in verdict.disagreeing] == [
        "newcombe_unchecked",
        "agresti_caffo_unchecked",
        "hierarchical_gamma_1_1_unchecked",
        "hierarchical_gamma_2_2_unchecked",
    ]


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
    verdict = conclude(cited, [placed("agresti_caffo", ABOVE_ZERO), moved])
    assert verdict == Conclusion(None, True, cited, (moved,))


def test_conclude_lists_every_disagreeing_method_in_input_order_and_no_agreeing_one():
    cited = placed("newcombe", ABOVE_ZERO)
    first = placed("agresti_caffo", BELOW_ZERO)
    second = placed("hierarchical", ACROSS_ZERO)
    verdict = conclude(cited, [first, placed("agreeing", ABOVE_ZERO), second])
    assert verdict.disagreeing == (first, second)


def test_conclude_lets_the_cited_placement_stand_without_other_methods():
    cited = placed("newcombe", BELOW_ZERO)
    assert conclude(cited, []) == Conclusion(Placement.BELOW, False, cited, ())


def test_observed_reads_the_share_sum_and_the_detected_runs_per_target():
    results = [
        _result("A", detected_runs=3, detected_runs_if_unchecked_missed=1),
        _result("B", detected_runs=1, detected_runs_if_unchecked_missed=0),
    ]
    side = split_by_side(results, RUN_CUTOFF)[Side.PRE_CUTOFF]

    reading = observed(side)

    assert math.isclose(reading.share_sum, 4 / RUNS)
    assert reading.counted_runs == (3, 1)
    assert reading.members == 2


def test_unchecked_as_misses_reads_the_runs_detected_with_every_unchecked_run_missed():
    results = [
        _result("A", detected_runs=3, detected_runs_if_unchecked_missed=1),
        _result("B", detected_runs=1, detected_runs_if_unchecked_missed=0),
    ]
    side = split_by_side(results, RUN_CUTOFF)[Side.PRE_CUTOFF]
    reading = unchecked_as_misses(side, RUNS)
    assert math.isclose(reading.share_sum, 1 / RUNS)
    assert reading.counted_runs == (1, 0)


def test_read_contrast_places_a_lopsided_gap_above_zero_under_the_four_suffixed_methods():
    placements = read_contrast(Reading(5.0, (3,) * 5), Reading(0.0, (0,) * 5), RUNS, "_suffix")
    assert [placement.method for placement in placements] == [
        "newcombe_suffix",
        "agresti_caffo_suffix",
        "hierarchical_gamma_1_1_suffix",
        "hierarchical_gamma_2_2_suffix",
    ]
    assert all(placement.placement is Placement.ABOVE for placement in placements)


def test_the_detection_rate_controls_are_the_five_intervals_on_the_detection_shares():
    results = [
        _result("A", detected_runs=3, detected_runs_if_unchecked_missed=2),
        _result("B", detected_runs=1, detected_runs_if_unchecked_missed=1),
    ]
    assert detection_rate_controls(results, RUNS) == {
        "jeffreys": jeffreys(4 / 3, 2),
        "clopper_pearson": clopper_pearson(4 / 3, 2),
        "hierarchical_gamma_1_1": hierarchical_interval([3, 1], RUNS, GammaPrior(1.0, 1.0)),
        "hierarchical_gamma_2_2": hierarchical_interval([3, 1], RUNS, GammaPrior(2.0, 2.0)),
        "unchecked_as_misses_wilson": wilson(3 / 3, 2),
    }


def test_unchecked_as_misses_control_is_wilson_on_the_recomputed_count():
    results = [
        _result("A", detected_runs=3, detected_runs_if_unchecked_missed=1),
        _result("B", detected_runs=2, detected_runs_if_unchecked_missed=0),
    ]
    recomputed = 1 / RUNS + 0 / RUNS
    controls = detection_rate_controls(results, RUNS)
    assert controls["unchecked_as_misses_wilson"] == wilson(recomputed, 2)
