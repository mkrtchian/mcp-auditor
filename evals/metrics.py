from collections import Counter

from pydantic import BaseModel

from evals.ground_truth import Cell, GroundTruth, cell_key
from mcp_auditor.domain.models import AuditCategory, AuditReport, EvalVerdict
from mcp_auditor.domain.rendering import MISSED_CALL_CAUSE_LABELS

type KeyedVerdicts[K] = dict[K, EvalVerdict | None]
VerdictMap = KeyedVerdicts[Cell]


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
    missed_model_calls: list[str] = []
    token_usage: dict[str, int]


class ConsistencyDetail(BaseModel):
    agree: int
    total: int
    rate: float


class HoneypotMetrics(BaseModel):
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
        for result in tool_report.judge_results:
            key = (result.tool_name, result.category)
            if verdicts.get(key) is None or result.verdict == EvalVerdict.FAIL:
                verdicts[key] = result.verdict
    return verdicts


def label_scores[K](
    verdict_maps: list[KeyedVerdicts[K]], ground_truth: dict[K, EvalVerdict]
) -> dict[str, float]:
    """Recall and precision averaged per run."""
    runs = len(verdict_maps)
    return {
        "recall": sum(compute_recall(verdicts, ground_truth) for verdicts in verdict_maps) / runs,
        "precision": sum(compute_precision(verdicts, ground_truth) for verdicts in verdict_maps)
        / runs,
    }


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


def compute_consistency(
    all_runs: list[VerdictMap],
    ground_truth: GroundTruth,
) -> tuple[float, dict[str, ConsistencyDetail]]:
    details: dict[str, ConsistencyDetail] = {}
    for key in sorted(ground_truth, key=lambda k: (k[0], k[1].value)):
        fail_count = sum(1 for run in all_runs if run.get(key) == EvalVerdict.FAIL)
        pass_count = sum(1 for run in all_runs if run.get(key) == EvalVerdict.PASS)
        total = fail_count + pass_count
        if total == 0:
            continue
        rate = max(fail_count, pass_count) / total
        details[cell_key(key)] = ConsistencyDetail(
            agree=max(fail_count, pass_count), total=total, rate=rate
        )

    if not details:
        return 1.0, {}
    avg = sum(d.rate for d in details.values()) / len(details)
    return avg, details


def build_run_detail(
    run_index: int,
    verdicts: VerdictMap,
    audit_report: AuditReport,
    ground_truth: GroundTruth,
) -> RunDetail:
    return RunDetail(
        run_index=run_index,
        verdicts=_verdict_detail(verdicts, audit_report),
        distribution=tool_distributions(audit_report),
        recall=compute_recall(verdicts, ground_truth),
        precision=compute_precision(verdicts, ground_truth),
        blocked_reasons=blocked_reasons(audit_report),
        missed_model_calls=missed_model_calls(audit_report),
        token_usage={
            "input_tokens": audit_report.provider_usage.input_tokens,
            "output_tokens": audit_report.provider_usage.output_tokens,
        },
    )


def tool_distributions(report: AuditReport) -> dict[str, ToolDistribution]:
    total = len(AuditCategory)
    distributions: dict[str, ToolDistribution] = {}
    for tool_report in report.tool_reports:
        covered = len(
            {case.judge_result.category for case in tool_report.cases if case.judge_result}
        )
        distributions[tool_report.tool.name] = ToolDistribution(
            covered=covered, total=total, coverage=covered / total
        )
    return distributions


def blocked_reasons(report: AuditReport) -> list[str]:
    return [
        reason
        for tool_report in report.tool_reports
        for reason in (
            [case.blocked_reason for case in tool_report.cases if case.blocked_reason]
            + [chain.blocked_reason for chain in tool_report.chains if chain.blocked_reason]
        )
    ]


def missed_model_calls(report: AuditReport) -> list[str]:
    return [
        f"{MISSED_CALL_CAUSE_LABELS[missed.cause]}, "
        f"{missed.tool_name}: {missed.kind}, {missed.detail}"
        for missed in report.missed_model_calls
    ]


def _verdict_detail(
    verdicts: VerdictMap,
    audit_report: AuditReport,
) -> dict[str, dict[str, ToolVerdictDetail]]:
    case_counts = Counter(
        (result.tool_name, result.category)
        for tool_report in audit_report.tool_reports
        for result in tool_report.judge_results
    )
    detail: dict[str, dict[str, ToolVerdictDetail]] = {}
    for (tool_name, category), verdict in verdicts.items():
        detail.setdefault(tool_name, {})[category.value] = ToolVerdictDetail(
            verdict=verdict.value if verdict is not None else "uncovered",
            case_count=case_counts[(tool_name, category)],
        )
    return detail


def average_distribution_coverage(run_details: list[RunDetail]) -> float:
    all_coverages = [dist.coverage for run in run_details for dist in run.distribution.values()]
    if not all_coverages:
        return 0.0
    return sum(all_coverages) / len(all_coverages)
