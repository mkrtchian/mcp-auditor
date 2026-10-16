"""Interval primitives for the holdout capability number: Wilson, Newcombe, Agresti-Caffo,
Jeffreys and Clopper-Pearson, with the regularized incomplete beta they rest on. Pure, `math`
only (Numerical Recipes continued fraction for the incomplete beta), so this module imports no
project code and no numpy or scipy.
"""

import math
from dataclasses import dataclass

Z_95 = 1.959963984540054
"""The two-sided 95 % normal quantile (the 0.975 point of the standard normal)."""


@dataclass(frozen=True)
class Interval:
    low: float
    high: float


def wilson(count: float, n: int) -> Interval:
    """Wilson score interval, no continuity correction; `count` may be a non-integer sum of
    detection shares."""
    p = count / n
    z2 = Z_95 * Z_95
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (Z_95 / denom) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return _proportion(center - half, center + half)


def newcombe(count_a: float, n_a: int, count_b: float, n_b: int) -> Interval:
    """Newcombe hybrid-score interval (method 10) for the difference p_a - p_b, combining each
    arm's Wilson bounds."""
    arm_a = wilson(count_a, n_a)
    arm_b = wilson(count_b, n_b)
    p_a = count_a / n_a
    p_b = count_b / n_b
    diff = p_a - p_b
    low = diff - math.sqrt((p_a - arm_a.low) ** 2 + (arm_b.high - p_b) ** 2)
    high = diff + math.sqrt((arm_a.high - p_a) ** 2 + (p_b - arm_b.low) ** 2)
    return _contrast(low, high)


def agresti_caffo(count_a: float, n_a: int, count_b: float, n_b: int) -> Interval:
    """Add one success and one failure per arm, then a Wald interval on the difference."""
    p_a = (count_a + 1) / (n_a + 2)
    p_b = (count_b + 1) / (n_b + 2)
    se = math.sqrt(p_a * (1 - p_a) / (n_a + 2) + p_b * (1 - p_b) / (n_b + 2))
    diff = p_a - p_b
    return _contrast(diff - Z_95 * se, diff + Z_95 * se)


def jeffreys(count: float, n: int) -> Interval:
    low = 0.0 if count <= 0 else beta_ppf(0.025, count + 0.5, n - count + 0.5)
    high = 1.0 if count >= n else beta_ppf(0.975, count + 0.5, n - count + 0.5)
    return _proportion(low, high)


def clopper_pearson(count: float, n: int) -> Interval:
    low = 0.0 if count <= 0 else beta_ppf(0.025, count, n - count + 1)
    high = 1.0 if count >= n else beta_ppf(0.975, count + 1, n - count)
    return _proportion(low, high)


def beta_ppf(p: float, a: float, b: float) -> float:
    """Quantile of the Beta(a, b) distribution: bisection on the regularized incomplete beta."""
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0
    low, high = 0.0, 1.0
    for _ in range(100):
        mid = (low + high) / 2
        if betainc(mid, a, b) < p:
            low = mid
        else:
            high = mid
    return (low + high) / 2


def betainc(x: float, a: float, b: float) -> float:
    """Regularized incomplete beta I_x(a, b), via the Numerical Recipes continued fraction."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_beta = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
    front = math.exp(a * math.log(x) + b * math.log1p(-x) - log_beta)
    if x < (a + 1) / (a + b + 2):
        return front * _betacf(x, a, b) / a
    return 1.0 - front * _betacf(1 - x, b, a) / b


def _betacf(x: float, a: float, b: float) -> float:
    tiny = 1e-30
    eps = 3e-16
    qab, qap, qam = a + b, a + 1, a - 1
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def _proportion(low: float, high: float) -> Interval:
    return Interval(_clamp(low, 0.0, 1.0), _clamp(high, 0.0, 1.0))


def _contrast(low: float, high: float) -> Interval:
    return Interval(_clamp(low, -1.0, 1.0), _clamp(high, -1.0, 1.0))


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))
