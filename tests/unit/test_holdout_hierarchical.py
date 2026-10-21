"""The hierarchical Beta-Binomial credible interval is a grid integral, so it is tested for
grid stability and prior direction rather than against a single closed form. The sanity anchor
below was computed offline with scipy on a 400x160 grid: 20 targets at runs=3 with pooled rate
0.833 give roughly (0.659, 0.917) under Gamma(1, 1), tightening toward the pool under Gamma(2, 2).
"""

from evals.holdout_hierarchical import (
    DEFAULT_GRID,
    GammaPrior,
    Grid,
    contrast_hierarchical,
    hierarchical_interval,
)

# 20 targets, runs = 3, pooled detected rate 50/60 = 0.833.
DETECTED = [3, 3, 2, 3, 1, 3, 3, 2, 3, 3, 0, 3, 3, 3, 2, 3, 3, 1, 3, 3]
RUNS = 3
FINER = Grid(theta_points=DEFAULT_GRID.theta_points * 2, d_points=DEFAULT_GRID.d_points * 2)


def test_matches_the_offline_scipy_anchor():
    interval = hierarchical_interval(DETECTED, RUNS, GammaPrior(1.0, 1.0))
    assert abs(interval.low - 0.659) < 0.01
    assert abs(interval.high - 0.917) < 0.01


# All-extreme anchors pinned against the module's own output under the untruncated prior
# (D_MIN = 1e-3, D_POINTS = 128), obtained by calling the two functions directly and reading
# back the bounds. They guard against a future re-truncation of the Gamma prior: raising D_MIN
# back to 0.1 shifts the all-detected lower bound by ~0.008 and the contrast lower bound by
# ~0.028, both far outside the tolerance below.
def test_all_detected_matches_the_offline_untruncated_value():
    interval = hierarchical_interval([3] * 20, RUNS, GammaPrior(1.0, 1.0))
    assert abs(interval.low - 0.879671) < 1e-4
    assert abs(interval.high - 0.997629) < 1e-4


def test_contrast_all_extreme_matches_the_offline_untruncated_value():
    interval = contrast_hierarchical([3] * 5, [0] * 5, RUNS, GammaPrior(1.0, 1.0))
    assert abs(interval.low - 0.407671) < 1e-4
    assert abs(interval.high - 0.970353) < 1e-4


def test_stable_between_the_module_grid_and_a_finer_grid():
    prior = GammaPrior(1.0, 1.0)
    module = hierarchical_interval(DETECTED, RUNS, prior)
    finer = hierarchical_interval(DETECTED, RUNS, prior, grid=FINER)
    assert abs(module.low - finer.low) < 0.005
    assert abs(module.high - finer.high) < 0.005


def test_more_concentration_pulls_toward_the_pooled_rate():
    diffuse = hierarchical_interval(DETECTED, RUNS, GammaPrior(1.0, 1.0))
    concentrated = hierarchical_interval(DETECTED, RUNS, GammaPrior(2.0, 2.0))
    # The pooled rate (0.833) sits above the diffuse interval's midpoint; a prior that pulls
    # per-target rates together shrinks the interval and lifts its lower bound toward the pool.
    assert (concentrated.high - concentrated.low) < (diffuse.high - diffuse.low)
    assert concentrated.low > diffuse.low


def test_an_all_missed_interval_clamps_its_low_bound_to_zero():
    assert hierarchical_interval([0] * 20, RUNS, GammaPrior(1.0, 1.0)).low == 0.0


COARSE = Grid(theta_points=120, d_points=48)


def test_contrast_straddles_zero_for_identical_sides():
    side = [3, 2, 3, 1, 3]
    interval = contrast_hierarchical(side, side, RUNS, GammaPrior(1.0, 1.0), grid=COARSE)
    assert interval.low < 0.0 < interval.high
    assert abs(interval.low + interval.high) < 0.05


def test_contrast_is_positive_when_side_a_detects_more():
    high_side = [3, 3, 3, 3, 3]
    low_side = [0, 0, 1, 0, 0]
    interval = contrast_hierarchical(high_side, low_side, RUNS, GammaPrior(1.0, 1.0), grid=COARSE)
    assert interval.low > 0.0
