from dataclasses import dataclass, field

from pydantic import BaseModel

from evals.ground_truth import GroundTruth
from mcp_auditor.domain.models import AuditCategory, AuditReport, EvalVerdict, ProviderUsage

type KeyedVerdicts[K] = dict[K, EvalVerdict | None]
VerdictMap = KeyedVerdicts[tuple[str, AuditCategory]]


class ToolVerdictDetail(BaseModel):
    verdict: str
    case_count: int


class ToolDistribution(BaseModel):
    covered: int
    total: int
    coverage: float


class RunDetail(BaseModel):
    run_index: int
    verdicts: dict[str, dict[str, ToolVerdictDetail]]
    distribution: dict[str, ToolDistribution]
    recall: float
    precision: float
    blocked_reasons: list[str] = []
    refused_steps: list[str] = []
    token_usage: dict[str, int]


class ConsistencyDetail(BaseModel):
    agree: int
    total: int
    rate: float


class EvalMetrics(BaseModel):
    recall: float
    precision: float
    consistency: float
    distribution_coverage: float


def aggregate_verdicts(report: AuditReport) -> VerdictMap:
    """Any-fail per (tool, category) cell: one FAIL among the cell's cases fails it.

    The generator spreads --budget over the categories, so a cell holds k cases that grow
    with the budget (chain verdicts count too). With q the per-case false-FAIL rate,
    P(cell FAIL) = 1 - (1-q)^k: a healthy cell fails more often as the budget rises, so two
    budgets do not measure the same thing (ADR 016).
    """
    verdicts: VerdictMap = {}
    for tool_report in report.tool_reports:
        for case in tool_report.cases:
            if case.eval_result is None:
                continue
            result = case.eval_result
            key = (result.tool_name, result.category)
            current = verdicts.get(key)
            if current is None or result.verdict == EvalVerdict.FAIL:
                verdicts[key] = result.verdict
        for chain in tool_report.chains:
            if chain.eval_result is None:
                continue
            result = chain.eval_result
            key = (result.tool_name, result.category)
            current = verdicts.get(key)
            if current is None or result.verdict == EvalVerdict.FAIL:
                verdicts[key] = result.verdict
    return verdicts


def compute_recall[K](aggregated: KeyedVerdicts[K], ground_truth: dict[K, EvalVerdict]) -> float:
    expected_fails = [key for key, verdict in ground_truth.items() if verdict == EvalVerdict.FAIL]
    if not expected_fails:
        return 1.0
    detected = sum(1 for key in expected_fails if aggregated.get(key) == EvalVerdict.FAIL)
    return detected / len(expected_fails)


def compute_precision[K](aggregated: KeyedVerdicts[K], ground_truth: dict[K, EvalVerdict]) -> float:
    predicted_fails = [
        key
        for key, verdict in aggregated.items()
        if verdict == EvalVerdict.FAIL and key in ground_truth
    ]
    if not predicted_fails:
        return 1.0
    correct = sum(1 for key in predicted_fails if ground_truth[key] == EvalVerdict.FAIL)
    return correct / len(predicted_fails)


def label_scores[K](
    verdict_maps: list[KeyedVerdicts[K]], ground_truth: dict[K, EvalVerdict]
) -> dict[str, float]:
    """Recall and precision averaged per run, as the report computes them."""
    runs = len(verdict_maps)
    return {
        "recall": sum(compute_recall(verdicts, ground_truth) for verdicts in verdict_maps) / runs,
        "precision": sum(compute_precision(verdicts, ground_truth) for verdicts in verdict_maps)
        / runs,
    }


def compute_consistency(
    all_runs: list[VerdictMap],
    ground_truth: GroundTruth,
) -> tuple[float, dict[str, ConsistencyDetail]]:
    details: dict[str, ConsistencyDetail] = {}
    for key in sorted(ground_truth, key=lambda k: (k[0], k[1].value)):
        tool_name, category = key
        fail_count = sum(1 for run in all_runs if run.get(key) == EvalVerdict.FAIL)
        pass_count = sum(1 for run in all_runs if run.get(key) == EvalVerdict.PASS)
        total = fail_count + pass_count
        if total == 0:
            continue
        rate = max(fail_count, pass_count) / total
        details[f"{tool_name}/{category.value}"] = ConsistencyDetail(
            agree=max(fail_count, pass_count), total=total, rate=rate
        )

    if not details:
        return 1.0, {}
    avg = sum(d.rate for d in details.values()) / len(details)
    return avg, details


def compute_distribution_coverage(
    report: AuditReport,
    categories: list[AuditCategory],
) -> dict[str, float]:
    coverage: dict[str, float] = {}
    for tool_report in report.tool_reports:
        covered = {case.eval_result.category for case in tool_report.cases if case.eval_result}
        coverage[tool_report.tool.name] = len(covered) / len(categories)
    return coverage


def blocked_reasons(report: AuditReport) -> list[str]:
    return [
        reason
        for tool_report in report.tool_reports
        for reason in (
            [case.blocked_reason for case in tool_report.cases if case.blocked_reason]
            + [chain.blocked_reason for chain in tool_report.chains if chain.blocked_reason]
        )
    ]


def refused_steps(report: AuditReport) -> list[str]:
    return [
        f"{refused.tool_name}: {refused.step}, {refused.provider_message}"
        for refused in report.refused_steps
    ]


@dataclass
class SessionThrottles:
    requests: int = 0
    usage: ProviderUsage = field(default_factory=ProviderUsage)

    def count(self, report: AuditReport) -> int:
        """Every report counted is billed, a refused attempt's and a replay's included."""
        return self.count_usage(report.provider_usage)

    def count_usage(self, usage: ProviderUsage) -> int:
        self.requests += usage.throttled_requests
        self.usage = self.usage.add(usage)
        return usage.throttled_requests


def build_run_detail(
    run_index: int,
    verdicts: VerdictMap,
    audit_report: AuditReport,
    ground_truth: GroundTruth,
) -> RunDetail:
    distribution = compute_distribution_coverage(audit_report, list(AuditCategory))
    return RunDetail(
        run_index=run_index,
        verdicts=_verdict_detail(verdicts, audit_report),
        distribution=_distribution_detail(distribution),
        recall=compute_recall(verdicts, ground_truth),
        precision=compute_precision(verdicts, ground_truth),
        blocked_reasons=blocked_reasons(audit_report),
        refused_steps=refused_steps(audit_report),
        token_usage={
            "input_tokens": audit_report.provider_usage.input_tokens,
            "output_tokens": audit_report.provider_usage.output_tokens,
        },
    )


def _verdict_detail(
    verdicts: VerdictMap,
    audit_report: AuditReport,
) -> dict[str, dict[str, ToolVerdictDetail]]:
    case_counts: dict[tuple[str, AuditCategory], int] = {}
    for tool_report in audit_report.tool_reports:
        judged = [case.eval_result for case in tool_report.cases] + [
            chain.eval_result for chain in tool_report.chains
        ]
        for result in judged:
            if result is None:
                continue
            key = (result.tool_name, result.category)
            case_counts[key] = case_counts.get(key, 0) + 1

    detail: dict[str, dict[str, ToolVerdictDetail]] = {}
    for (tool_name, category), verdict in verdicts.items():
        detail.setdefault(tool_name, {})[category.value] = ToolVerdictDetail(
            verdict=verdict.value if verdict is not None else "uncovered",
            case_count=case_counts.get((tool_name, category), 0),
        )
    return detail


def _distribution_detail(distribution: dict[str, float]) -> dict[str, ToolDistribution]:
    total = len(AuditCategory)
    return {
        tool_name: ToolDistribution(
            covered=round(coverage * total),
            total=total,
            coverage=coverage,
        )
        for tool_name, coverage in distribution.items()
    }


def average_distribution_coverage(run_details: list[RunDetail]) -> float:
    all_coverages = [dist.coverage for run in run_details for dist in run.distribution.values()]
    if not all_coverages:
        return 0.0
    return sum(all_coverages) / len(all_coverages)
