from dataclasses import dataclass

from mcp_auditor.domain.models import AuditCategory, EvalVerdict


@dataclass(frozen=True)
class ConfusionMatrix:
    tp: int
    fp: int
    tn: int
    fn: int


@dataclass(frozen=True)
class JudgeMetrics:
    precision: float
    recall: float
    f1: float
    confusion: ConfusionMatrix


CaseResult = tuple[EvalVerdict, EvalVerdict]  # (predicted, expected)


def compute_judge_metrics(results: list[CaseResult]) -> JudgeMetrics:
    tp = sum(1 for p, e in results if p == EvalVerdict.FAIL and e == EvalVerdict.FAIL)
    fp = sum(1 for p, e in results if p == EvalVerdict.FAIL and e == EvalVerdict.PASS)
    tn = sum(1 for p, e in results if p == EvalVerdict.PASS and e == EvalVerdict.PASS)
    fn = sum(1 for p, e in results if p == EvalVerdict.PASS and e == EvalVerdict.FAIL)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return JudgeMetrics(
        precision=precision,
        recall=recall,
        f1=f1,
        confusion=ConfusionMatrix(tp=tp, fp=fp, tn=tn, fn=fn),
    )


def compute_per_category_metrics(
    results: list[tuple[AuditCategory, CaseResult]],
) -> dict[AuditCategory, JudgeMetrics]:
    by_category: dict[AuditCategory, list[CaseResult]] = {}
    for category, case_result in results:
        by_category.setdefault(category, []).append(case_result)
    return {cat: compute_judge_metrics(cases) for cat, cases in by_category.items()}
