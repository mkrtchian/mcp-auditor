from pydantic import BaseModel

from evals.ground_truth import GroundTruth
from mcp_auditor.domain.models import AuditCategory, AuditReport, EvalVerdict

VerdictMap = dict[tuple[str, AuditCategory], EvalVerdict | None]


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


class EvalReport(BaseModel):
    timestamp: str
    config: dict[str, int]
    metrics: EvalMetrics
    thresholds: dict[str, float]
    passed: bool
    runs: list[RunDetail]
    consistency_details: dict[str, ConsistencyDetail]


def aggregate_verdicts(report: AuditReport) -> VerdictMap:
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


def compute_recall(aggregated: VerdictMap, ground_truth: GroundTruth) -> float:
    expected_fails = [key for key, verdict in ground_truth.items() if verdict == EvalVerdict.FAIL]
    if not expected_fails:
        return 1.0
    detected = sum(1 for key in expected_fails if aggregated.get(key) == EvalVerdict.FAIL)
    return detected / len(expected_fails)


def compute_precision(aggregated: VerdictMap, ground_truth: GroundTruth) -> float:
    predicted_fails = [key for key, verdict in aggregated.items() if verdict == EvalVerdict.FAIL]
    if not predicted_fails:
        return 1.0
    correct = sum(1 for key in predicted_fails if ground_truth.get(key) == EvalVerdict.FAIL)
    return correct / len(predicted_fails)


def compute_consistency(
    all_runs: list[VerdictMap],
) -> tuple[float, dict[str, ConsistencyDetail]]:
    all_keys: set[tuple[str, AuditCategory]] = set()
    for run in all_runs:
        all_keys.update(run.keys())

    details: dict[str, ConsistencyDetail] = {}
    for key in sorted(all_keys, key=lambda k: (k[0], k[1].value)):
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
