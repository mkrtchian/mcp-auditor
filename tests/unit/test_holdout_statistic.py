"""The holdout aggregation over per-target results: the primary number, the cutoff-side split,
the contrast and the conclusion check. Reference values are the direct interval calls on the
crafted counts; nothing is fetched."""

import math
from datetime import date

from evals.census_draw import Side
from evals.holdout_intervals import newcombe, wilson
from evals.holdout_results import HoldoutTargetResult
from evals.holdout_statistic import (
    Placement,
    check_conclusion,
    cited_interval,
    contrast,
    primary_controls,
    primary_number,
    split_by_side,
)

RUN_CUTOFF = date(2026, 5, 18)
RUNS = 3


def _result(
    cve_id: str = "CVE-0000-0000",
    *,
    disclosure_date: date = date(2026, 1, 1),
    detected_runs: int = 0,
    detected_runs_if_unchecked_missed: int = 0,
    runs: int = RUNS,
) -> HoldoutTargetResult:
    return HoldoutTargetResult(
        cve_id=cve_id,
        disclosure_date=disclosure_date,
        mechanism_label="read_outside_scope",
        tools_count=4,
        ran_in_fallback=False,
        runs=runs,
        detected_runs=detected_runs,
        detection_share=detected_runs / runs,
        detected_runs_if_unchecked_missed=detected_runs_if_unchecked_missed,
        surfaced_places=[[] for _ in range(runs)],
        struck_places=[[] for _ in range(runs)],
        unchecked_places=[[] for _ in range(runs)],
        aimed_runs=detected_runs,
        fail_without_proof_runs=0,
        incomplete_runs=0,
        run_cost=0.01,
    )


def test_primary_number_is_the_sum_of_shares_over_the_target_count():
    results = [
        _result("A", detected_runs=3),  # share 1.0
        _result("B", detected_runs=1),  # share 1/3
        _result("C", detected_runs=0),  # share 0.0
    ]
    expected = (3 / 3 + 1 / 3 + 0 / 3) / 3
    assert math.isclose(primary_number(results), expected)
    assert math.isclose(primary_number(results), sum(r.detection_share for r in results) / 3)


def test_cited_interval_is_wilson_on_the_sum_of_shares():
    results = [_result("A", detected_runs=3), _result("B", detected_runs=1)]
    share_sum = 3 / 3 + 1 / 3
    assert cited_interval(results) == wilson(share_sum, 2)


def test_split_by_side_recomputes_the_side_from_the_disclosure_date():
    pre_by_date = _result("PRE", disclosure_date=date(2026, 1, 1), detected_runs=3)
    post_by_date = _result("POST", disclosure_date=date(2026, 12, 1), detected_runs=0)
    split = split_by_side([pre_by_date, post_by_date], RUN_CUTOFF)
    assert [r.cve_id for r in split[Side.PRE_CUTOFF].results] == ["PRE"]
    assert [r.cve_id for r in split[Side.POST_CUTOFF].results] == ["POST"]


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


def _lopsided_sides(unchecked_pre: int):
    pre = [
        _result(
            f"PRE{i}",
            disclosure_date=date(2026, 1, 1),
            detected_runs=3,
            detected_runs_if_unchecked_missed=unchecked_pre,
        )
        for i in range(5)
    ]
    post = [
        _result(f"POST{i}", disclosure_date=date(2026, 12, 1), detected_runs=0) for i in range(5)
    ]
    split = split_by_side(pre + post, RUN_CUTOFF)
    return split[Side.PRE_CUTOFF], split[Side.POST_CUTOFF]


def test_check_conclusion_agrees_when_every_method_places_the_gap_above_zero():
    pre, post = _lopsided_sides(unchecked_pre=3)
    verdict = check_conclusion(pre, post, RUNS)
    assert verdict is not None
    assert verdict.inconclusive is False
    assert verdict.placement is Placement.ABOVE
    assert verdict.disagreeing == ()


def test_check_conclusion_is_inconclusive_when_unchecked_as_misses_moves_the_placement():
    pre, post = _lopsided_sides(unchecked_pre=0)
    verdict = check_conclusion(pre, post, RUNS)
    assert verdict is not None
    assert verdict.inconclusive is True
    assert verdict.placement is None
    disagreeing = {method.method for method in verdict.disagreeing}
    assert "newcombe_unchecked" in disagreeing


def test_check_conclusion_is_none_below_five_targets_a_side():
    pre, post = _split_sides(4, 4, detected_runs=3)
    assert check_conclusion(pre, post, RUNS) is None


def test_primary_controls_returns_the_five_named_controls():
    results = [_result("A", detected_runs=3), _result("B", detected_runs=1)]
    controls = primary_controls(results, RUNS)
    assert set(controls) == {
        "jeffreys",
        "clopper_pearson",
        "hierarchical_gamma_1_1",
        "hierarchical_gamma_2_2",
        "unchecked_as_misses_wilson",
    }


def test_unchecked_as_misses_control_is_wilson_on_the_recomputed_count():
    results = [
        _result("A", detected_runs=3, detected_runs_if_unchecked_missed=1),
        _result("B", detected_runs=2, detected_runs_if_unchecked_missed=0),
    ]
    recomputed = 1 / RUNS + 0 / RUNS
    controls = primary_controls(results, RUNS)
    assert controls["unchecked_as_misses_wilson"] == wilson(recomputed, 2)
