"""The hierarchical Beta-Binomial credible interval for the holdout capability number, kept
apart from holdout_intervals because it integrates over a grid. Each target's detected runs are
Binomial, its rate Beta with mean theta and concentration d, so its marginal is Beta-Binomial;
the posterior on theta marginalises d over a grid. Pure, `math` only, no numpy or scipy.
"""

import math
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from evals.holdout_intervals import Interval

THETA_POINTS = 320
D_POINTS = 128
D_MIN = 0.1
D_MAX = 2000.0


@dataclass(frozen=True)
class Grid:
    theta_points: int = THETA_POINTS
    d_points: int = D_POINTS


@dataclass(frozen=True)
class GammaPrior:
    shape: float
    scale: float


DEFAULT_GRID = Grid()


def hierarchical_interval(
    detected_per_target: Sequence[int],
    runs: int,
    d_prior: GammaPrior,
    grid: Grid = DEFAULT_GRID,
) -> Interval:
    """95 % equal-tailed credible interval on the shared mean rate theta, marginalising the
    concentration d under its Gamma prior; theta ~ Beta(1, 1)."""
    thetas = _theta_grid(grid.theta_points)
    ds = _d_grid(grid.d_points)
    log_prior_d = [_gamma_logpdf(d, d_prior) + math.log(d) for d in ds]
    counts = Counter(detected_per_target)

    def marginal(theta: float) -> float:
        return _logsumexp(
            [_side_loglik(counts, runs, theta, d) + log_prior_d[j] for j, d in enumerate(ds)]
        )

    masses = _normalize([marginal(theta) for theta in thetas])
    low, high = _equal_tailed(thetas, masses)
    return Interval(max(0.0, low), min(1.0, high))


def contrast_hierarchical(
    side_a: Sequence[int],
    side_b: Sequence[int],
    runs: int,
    d_prior: GammaPrior,
    grid: Grid = DEFAULT_GRID,
) -> Interval:
    """95 % equal-tailed credible interval on theta_a - theta_b, the two sides sharing one
    concentration d."""
    thetas = _theta_grid(grid.theta_points)
    ds = _d_grid(grid.d_points)
    log_prior_d = [_gamma_logpdf(d, d_prior) + math.log(d) for d in ds]
    counts_a = Counter(side_a)
    counts_b = Counter(side_b)
    diff_mass = _difference_mass(thetas, ds, log_prior_d, counts_a, counts_b, runs)
    low, high = _equal_tailed(_difference_support(thetas), diff_mass)
    return Interval(max(-1.0, low), min(1.0, high))


def _difference_mass(
    thetas: list[float],
    ds: list[float],
    log_prior_d: list[float],
    counts_a: Counter[int],
    counts_b: Counter[int],
    runs: int,
) -> list[float]:
    size = 2 * len(thetas) - 1
    mass = [0.0] * size
    offset = len(thetas) - 1
    log_evidence, cond_a, cond_b = _per_d_terms(thetas, ds, log_prior_d, counts_a, counts_b, runs)
    ceiling = max(log_evidence)
    for j in range(len(ds)):
        weight = math.exp(log_evidence[j] - ceiling)
        for ia, pa in enumerate(cond_a[j]):
            if pa == 0.0:
                continue
            base = weight * pa
            for ib, pb in enumerate(cond_b[j]):
                mass[ia - ib + offset] += base * pb
    return mass


def _per_d_terms(
    thetas: list[float],
    ds: list[float],
    log_prior_d: list[float],
    counts_a: Counter[int],
    counts_b: Counter[int],
    runs: int,
) -> tuple[list[float], list[list[float]], list[list[float]]]:
    """Per-d log evidence (prior times each side's marginal over theta) and the two
    theta-conditionals normalised to sum to one; the side marginals must keep their own scale so
    the shared concentration d is weighted by its true evidence, not a per-d ceiling."""
    log_evidence: list[float] = []
    cond_a: list[list[float]] = []
    cond_b: list[list[float]] = []
    for j, d in enumerate(ds):
        logs_a = [_side_loglik(counts_a, runs, theta, d) for theta in thetas]
        logs_b = [_side_loglik(counts_b, runs, theta, d) for theta in thetas]
        lse_a, lse_b = _logsumexp(logs_a), _logsumexp(logs_b)
        log_evidence.append(log_prior_d[j] + lse_a + lse_b)
        cond_a.append([math.exp(value - lse_a) for value in logs_a])
        cond_b.append([math.exp(value - lse_b) for value in logs_b])
    return log_evidence, cond_a, cond_b


def _side_loglik(counts: Counter[int], runs: int, theta: float, d: float) -> float:
    a = theta * d
    b = (1 - theta) * d
    return sum(times * _betabinom_logpmf(k, runs, a, b) for k, times in counts.items())


def _betabinom_logpmf(k: int, n: int, a: float, b: float) -> float:
    return (
        math.lgamma(k + a)
        + math.lgamma(n - k + b)
        - math.lgamma(n + a + b)
        + math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
    )


def _gamma_logpdf(d: float, prior: GammaPrior) -> float:
    return (
        (prior.shape - 1) * math.log(d)
        - d / prior.scale
        - math.lgamma(prior.shape)
        - prior.shape * math.log(prior.scale)
    )


def _theta_grid(points: int) -> list[float]:
    return [(i + 0.5) / points for i in range(points)]


def _d_grid(points: int) -> list[float]:
    step = (math.log(D_MAX) - math.log(D_MIN)) / (points - 1)
    return [math.exp(math.log(D_MIN) + step * j) for j in range(points)]


def _difference_support(thetas: list[float]) -> list[float]:
    width = thetas[1] - thetas[0]
    count = len(thetas)
    return [(index - (count - 1)) * width for index in range(2 * count - 1)]


def _logsumexp(values: list[float]) -> float:
    ceiling = max(values)
    return ceiling + math.log(sum(math.exp(value - ceiling) for value in values))


def _normalize(log_values: list[float]) -> list[float]:
    ceiling = max(log_values)
    weights = [math.exp(value - ceiling) for value in log_values]
    total = sum(weights)
    return [weight / total for weight in weights]


def _equal_tailed(support: list[float], masses: list[float]) -> tuple[float, float]:
    total = sum(masses)
    cumulative: list[float] = []
    running = 0.0
    for mass in masses:
        running += mass / total
        cumulative.append(running)
    return _quantile(support, cumulative, 0.025), _quantile(support, cumulative, 0.975)


def _quantile(support: list[float], cumulative: list[float], p: float) -> float:
    for i in range(1, len(support)):
        if cumulative[i] >= p:
            span = cumulative[i] - cumulative[i - 1]
            fraction = 0.0 if span == 0.0 else (p - cumulative[i - 1]) / span
            return support[i - 1] + fraction * (support[i] - support[i - 1])
    return support[-1]
