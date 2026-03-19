from evals.judge_metrics import (
    CaseResult,
    compute_judge_metrics,
    compute_per_category_metrics,
)
from mcp_auditor.domain.models import AuditCategory, EvalVerdict

FAIL = EvalVerdict.FAIL
PASS = EvalVerdict.PASS


def _tp() -> CaseResult:
    return (FAIL, FAIL)


def _tn() -> CaseResult:
    return (PASS, PASS)


def _fp() -> CaseResult:
    return (FAIL, PASS)


def _fn() -> CaseResult:
    return (PASS, FAIL)


def test_all_correct() -> None:
    results = [_tp() for _ in range(5)] + [_tn() for _ in range(5)]
    metrics = compute_judge_metrics(results)
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1 == 1.0


def test_all_wrong() -> None:
    results = [_fp() for _ in range(5)] + [_fn() for _ in range(5)]
    metrics = compute_judge_metrics(results)
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1 == 0.0


def test_one_false_positive() -> None:
    results = [_tp() for _ in range(4)] + [_fp()] + [_tn() for _ in range(5)]
    metrics = compute_judge_metrics(results)
    assert metrics.precision == 0.8
    assert metrics.recall == 1.0


def test_one_false_negative() -> None:
    results = [_tp() for _ in range(4)] + [_fn()] + [_tn() for _ in range(5)]
    metrics = compute_judge_metrics(results)
    assert metrics.precision == 1.0
    assert metrics.recall == 0.8


def test_no_positives() -> None:
    results = [_tn() for _ in range(10)]
    metrics = compute_judge_metrics(results)
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0


def test_no_predictions() -> None:
    results = [_tn() for _ in range(5)] + [_fn() for _ in range(5)]
    metrics = compute_judge_metrics(results)
    assert metrics.precision == 1.0
    assert metrics.recall == 0.0


def test_per_category_separates() -> None:
    results: list[tuple[AuditCategory, CaseResult]] = [
        (AuditCategory.INJECTION, _tp()),
        (AuditCategory.INJECTION, _tp()),
        (AuditCategory.INFO_LEAKAGE, _fp()),
        (AuditCategory.INFO_LEAKAGE, _tn()),
    ]
    per_cat = compute_per_category_metrics(results)
    assert per_cat[AuditCategory.INJECTION].precision == 1.0
    assert per_cat[AuditCategory.INJECTION].recall == 1.0
    assert per_cat[AuditCategory.INFO_LEAKAGE].precision == 0.0
    assert per_cat[AuditCategory.INFO_LEAKAGE].recall == 1.0


def test_confusion_matrix_counts() -> None:
    results = [_tp(), _tp(), _tp(), _fp(), _fp(), _tn(), _fn()]
    metrics = compute_judge_metrics(results)
    assert metrics.confusion.tp == 3
    assert metrics.confusion.fp == 2
    assert metrics.confusion.tn == 1
    assert metrics.confusion.fn == 1
