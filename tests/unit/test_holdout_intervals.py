"""Reference values are computed offline with scipy (scipy.stats.beta / scipy.stats.norm)
and the published closed forms, then hardcoded here; the production code uses `math` only.
Each block records how its numbers were obtained. Nothing here is fetched at test time.
"""

import math

import pytest

from evals.holdout_intervals import (
    Z_95,
    Interval,
    agresti_caffo,
    beta_ppf,
    betainc,
    clopper_pearson,
    jeffreys,
    newcombe,
    wilson,
)

TOL = 1e-9


def _close(interval: Interval, low: float, high: float) -> bool:
    return math.isclose(interval.low, low, abs_tol=TOL) and math.isclose(
        interval.high, high, abs_tol=TOL
    )


def test_z_is_the_two_sided_95_percent_normal_quantile():
    # scipy.stats.norm.ppf(0.975) == 1.959963984540054
    assert Z_95 == 1.959963984540054


# Wilson score interval, no continuity correction (closed form, computed offline):
#   center = (p + z^2/2n) / (1 + z^2/n)
#   half   = (z / (1 + z^2/n)) * sqrt(p(1-p)/n + z^2/4n^2)
@pytest.mark.parametrize(
    "count, n, low, high",
    [
        (0, 20, 0.0, 0.16112515805281938),
        (10, 20, 0.2992980081982123, 0.7007019918017877),
        (8, 10, 0.4901624715366418, 0.9433178485456248),
        # non-integer count (sum of detection shares), hand-computed from the same formula
        (3.5, 20, 0.06610623089104362, 0.388625121843289),
    ],
)
def test_wilson_matches_reference(count: float, n: int, low: float, high: float):
    assert _close(wilson(count, n), low, high)


# Clopper-Pearson via Beta quantiles:
#   low  = Beta.ppf(0.025, k, n-k+1)   (0 when k == 0)
#   high = Beta.ppf(0.975, k+1, n-k)   (1 when k == n)
# reference from scipy.stats.beta.ppf.
@pytest.mark.parametrize(
    "count, n, low, high",
    [
        (0, 20, 0.0, 0.1684334709830853),
        (10, 20, 0.27195784956079183, 0.7280421504392081),
        (8, 10, 0.4439045376923585, 0.9747892736731666),
        (3.5, 20, 0.04413134197515587, 0.4082257625169254),
    ],
)
def test_clopper_pearson_matches_reference(count: float, n: int, low: float, high: float):
    assert _close(clopper_pearson(count, n), low, high)


# Jeffreys interval: Beta.ppf(0.025 / 0.975, k+0.5, n-k+0.5), edges clamped.
@pytest.mark.parametrize(
    "count, n, low, high",
    [
        (0, 20, 0.0, 0.11663898290487539),
        (10, 20, 0.29337648473319405, 0.7066235152668059),
        (8, 10, 0.4972255035600069, 0.9559405864473692),
        (3.5, 20, 0.05733399705003277, 0.37892682654531396),
    ],
)
def test_jeffreys_matches_reference(count: float, n: int, low: float, high: float):
    assert _close(jeffreys(count, n), low, high)


# beta_ppf reference quantiles from scipy.stats.beta.ppf(p, a, b).
@pytest.mark.parametrize(
    "p, a, b, expected",
    [
        (0.5, 2, 3, 0.3857275681323895),
        (0.025, 5, 16, 0.08657146910143461),
        (0.975, 11, 10, 0.7280421504392081),
        (0.025, 4.0, 18.0, 0.05446356817840681),
        (0.975, 4.5, 17.5, 0.39167251430003275),
        (0.1, 1, 1, 0.1),
        (0.9, 0.5, 0.5, 0.9755282581475768),
    ],
)
def test_beta_ppf_matches_reference(p: float, a: float, b: float, expected: float):
    assert math.isclose(beta_ppf(p, a, b), expected, abs_tol=TOL)


# betainc is the inverse relation of beta_ppf: I_x(a, b) at the quantile returns p.
def test_betainc_inverts_beta_ppf():
    for p, a, b in [(0.3, 2.0, 5.0), (0.7, 4.5, 3.5), (0.025, 5.0, 16.0)]:
        assert math.isclose(betainc(beta_ppf(p, a, b), a, b), p, abs_tol=1e-9)


def test_betainc_at_the_edges():
    assert betainc(0.0, 2.0, 3.0) == 0.0
    assert betainc(1.0, 2.0, 3.0) == 1.0


# Newcombe hybrid-score interval for the difference p_a - p_b (method 10):
#   low  = (p1-p2) - sqrt((p1-l1)^2 + (u2-p2)^2)
#   high = (p1-p2) + sqrt((u1-p1)^2 + (p2-l2)^2)
# with (l,u) each arm's Wilson bounds; reference computed offline from that formula.
@pytest.mark.parametrize(
    "ca, na, cb, nb, low, high",
    [
        (8, 10, 5, 20, 0.17075157493340704, 0.7490532472725114),
        (10, 20, 10, 20, -0.28383547880138194, 0.28383547880138194),
        (3.5, 20, 7.5, 20, -0.4414593134429795, 0.0762986531039655),
    ],
)
def test_newcombe_matches_reference(
    ca: float, na: int, cb: float, nb: int, low: float, high: float
):
    assert _close(newcombe(ca, na, cb, nb), low, high)


# Agresti-Caffo: add one success and one failure per arm, then Wald on the difference.
@pytest.mark.parametrize(
    "ca, na, cb, nb, low, high",
    [
        (8, 10, 5, 20, 0.16960970950516607, 0.7849357450402885),
        (10, 20, 10, 20, -0.2954756881513314, 0.2954756881513314),
        (3.5, 20, 7.5, 20, -0.44603140824702514, 0.08239504461066158),
    ],
)
def test_agresti_caffo_matches_reference(
    ca: float, na: int, cb: float, nb: int, low: float, high: float
):
    assert _close(agresti_caffo(ca, na, cb, nb), low, high)


def test_proportion_intervals_clamp_to_zero_one():
    assert wilson(0, 20).low == 0.0
    assert wilson(20, 20).high == 1.0
    assert clopper_pearson(0, 20).low == 0.0
    assert jeffreys(20, 20).high == 1.0


def test_contrast_intervals_clamp_to_minus_one_one():
    # agresti_caffo(0, 20, 20, 20) is (-1.0321854..., -0.7859963...) before clamping.
    clamped = agresti_caffo(0, 20, 20, 20)
    assert clamped.low == -1.0
    assert clamped.high >= -1.0
    # newcombe(0, 20, 20, 20) lower bound is exactly -1 after clamping.
    assert newcombe(0, 20, 20, 20).low == -1.0
