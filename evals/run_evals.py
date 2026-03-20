import argparse
import asyncio
import os
import sys
import traceback
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from evals.export import export_judged_cases
from evals.ground_truth import HONEYPOT_GROUND_TRUTH, SUBTLE_GROUND_TRUTH, GroundTruth
from evals.metrics import (
    EvalMetrics,
    EvalReport,
    RunDetail,
    ToolDistribution,
    ToolVerdictDetail,
    VerdictMap,
    aggregate_verdicts,
    compute_consistency,
    compute_distribution_coverage,
    compute_precision,
    compute_recall,
)
from mcp_auditor.adapters.llm import create_judge_llm, create_llm
from mcp_auditor.adapters.mcp_client import StdioMCPClient
from mcp_auditor.config import Settings, load_settings
from mcp_auditor.domain.models import AuditCategory, AuditReport, TokenUsage, ToolReport
from mcp_auditor.graph.builder import build_graph

HONEYPOT_SERVER = Path(__file__).resolve().parent.parent / "tests" / "dummy_server.py"
SUBTLE_SERVER = Path(__file__).resolve().parent.parent / "tests" / "subtle_server.py"


@dataclass(frozen=True)
class HoneypotConfig:
    name: str
    command: str
    args: list[str]
    ground_truth: GroundTruth


@dataclass(frozen=True)
class EvalRunResult:
    report: EvalReport
    runs: list[tuple[int, AuditReport]]
    ground_truth: GroundTruth


HONEYPOTS = [
    HoneypotConfig(
        name="honeypot",
        command="uv",
        args=["run", "python", str(HONEYPOT_SERVER)],
        ground_truth=HONEYPOT_GROUND_TRUTH,
    ),
    HoneypotConfig(
        name="subtle",
        command="uv",
        args=["run", "python", str(SUBTLE_SERVER)],
        ground_truth=SUBTLE_GROUND_TRUTH,
    ),
]

DEFAULT_RUNS = 3
DEFAULT_BUDGET = 10
DEFAULT_REPORT_PATH = "evals/eval_report.json"

THRESHOLDS: dict[str, float] = {
    "recall": 0.80,
    "precision": 0.85,
    "consistency": 0.70,
    "distribution_coverage": 0.80,
}

ALL_CATEGORIES = list(AuditCategory)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run evals against the honeypot")
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    parser.add_argument("--report", type=str, default=DEFAULT_REPORT_PATH)
    args = parser.parse_args()

    result = asyncio.run(run_evals(args.runs, args.budget))

    report_path = Path(args.report)
    report_path.write_text(result.report.model_dump_json(indent=2))
    export_judged_cases(result.runs, result.ground_truth, report_path)
    _print_summary(result.report, args.report)

    if result.report.passed:
        print("\nAll thresholds met.")
    else:
        print("\nSome thresholds not met.")
        raise SystemExit(1)


async def run_evals(num_runs: int, budget: int) -> EvalRunResult:
    settings = load_settings()
    run_details: list[RunDetail] = []
    all_verdict_maps: list[VerdictMap] = []
    accumulated_runs: list[tuple[int, AuditReport]] = []
    merged_ground_truth: GroundTruth = {}
    for honeypot in HONEYPOTS:
        merged_ground_truth.update(honeypot.ground_truth)

    for i in range(num_runs):
        print(f"\nRunning eval {i + 1}/{num_runs}...")
        try:
            verdicts, ground_truth, audit_report = await _run_one_eval(settings, budget)
        except Exception:
            print(f"Warning: run {i + 1}/{num_runs} failed:")
            traceback.print_exc(file=sys.stdout)
            continue

        all_verdict_maps.append(verdicts)
        accumulated_runs.append((i, audit_report))

        run_detail = _build_run_detail(i, verdicts, audit_report, ground_truth)
        _post_langsmith_feedback(
            run_detail.recall, run_detail.precision, settings.langsmith_project
        )
        run_details.append(run_detail)
        _print_run_result(run_detail)

    if not run_details:
        print("All runs failed. Cannot produce eval report.")
        raise SystemExit(1)

    report = _assemble_report(num_runs, budget, run_details, all_verdict_maps)
    return EvalRunResult(
        report=report,
        runs=accumulated_runs,
        ground_truth=merged_ground_truth,
    )


async def _run_one_eval(
    settings: Settings, budget: int
) -> tuple[VerdictMap, GroundTruth, AuditReport]:
    merged_verdicts: VerdictMap = {}
    merged_ground_truth: GroundTruth = {}
    all_tool_reports: list[ToolReport] = []
    total_usage = TokenUsage()

    for honeypot in HONEYPOTS:
        print(f"  Auditing {honeypot.name}...")
        report = await _run_single_honeypot(settings, honeypot, budget)
        verdicts = aggregate_verdicts(report)
        merged_verdicts.update(verdicts)
        merged_ground_truth.update(honeypot.ground_truth)
        all_tool_reports.extend(report.tool_reports)
        total_usage = total_usage.add(report.token_usage)

    merged_report = AuditReport(
        target="evals",
        tool_reports=all_tool_reports,
        token_usage=total_usage,
    )
    return merged_verdicts, merged_ground_truth, merged_report


async def _run_single_honeypot(
    settings: Settings, honeypot: HoneypotConfig, budget: int
) -> AuditReport:
    llm = create_llm(settings)
    judge_llm = create_judge_llm(settings)
    async with StdioMCPClient.connect(honeypot.command, honeypot.args) as mcp_client:
        graph = build_graph(llm, mcp_client, judge_llm=judge_llm)
        result = await graph.ainvoke(  # pyright: ignore[reportUnknownMemberType]
            {"target": f"{honeypot.command} {' '.join(honeypot.args)}", "test_budget": budget}
        )
        return result["audit_report"]


def _post_langsmith_feedback(
    recall: float,
    precision: float,
    project_name: str,
) -> None:
    if not os.environ.get("LANGCHAIN_TRACING_V2"):
        return
    try:
        from langsmith import Client  # type: ignore[import-untyped]

        client = Client()
        runs = list(
            client.list_runs(
                project_name=project_name,
                limit=1,
            )
        )
        if not runs:
            return
        run_id = runs[0].id
        client.create_feedback(run_id, key="recall", score=recall)  # pyright: ignore[reportUnknownMemberType]
        client.create_feedback(run_id, key="precision", score=precision)  # pyright: ignore[reportUnknownMemberType]
    except Exception:
        pass  # Best-effort — don't fail evals because of LangSmith


def _build_run_detail(
    run_index: int,
    verdicts: VerdictMap,
    audit_report: AuditReport,
    ground_truth: GroundTruth,
) -> RunDetail:
    recall = compute_recall(verdicts, ground_truth)
    precision = compute_precision(verdicts, ground_truth)
    distribution = compute_distribution_coverage(audit_report, ALL_CATEGORIES)
    verdict_detail = _build_verdict_detail(verdicts, audit_report)
    distribution_detail = _build_distribution_detail(distribution)
    return RunDetail(
        run_index=run_index,
        verdicts=verdict_detail,
        distribution=distribution_detail,
        recall=recall,
        precision=precision,
        token_usage={
            "input_tokens": audit_report.token_usage.input_tokens,
            "output_tokens": audit_report.token_usage.output_tokens,
        },
    )


def _build_verdict_detail(
    verdicts: VerdictMap,
    audit_report: AuditReport,
) -> dict[str, dict[str, ToolVerdictDetail]]:
    case_counts: dict[tuple[str, AuditCategory], int] = {}
    for tool_report in audit_report.tool_reports:
        for case in tool_report.cases:
            if case.eval_result is None:
                continue
            result = case.eval_result
            key = (result.tool_name, result.category)
            case_counts[key] = case_counts.get(key, 0) + 1

    detail: dict[str, dict[str, ToolVerdictDetail]] = {}
    for (tool_name, category), verdict in verdicts.items():
        if tool_name not in detail:
            detail[tool_name] = {}
        detail[tool_name][category.value] = ToolVerdictDetail(
            verdict=verdict.value if verdict is not None else "uncovered",
            case_count=case_counts.get((tool_name, category), 0),
        )
    return detail


def _build_distribution_detail(
    distribution: dict[str, float],
) -> dict[str, ToolDistribution]:
    total = len(ALL_CATEGORIES)
    return {
        tool_name: ToolDistribution(
            covered=round(coverage * total),
            total=total,
            coverage=coverage,
        )
        for tool_name, coverage in distribution.items()
    }


def _assemble_report(
    num_runs: int,
    budget: int,
    run_details: list[RunDetail],
    all_verdict_maps: list[VerdictMap],
) -> EvalReport:
    avg_recall = sum(r.recall for r in run_details) / len(run_details)
    avg_precision = sum(r.precision for r in run_details) / len(run_details)
    consistency, consistency_details = compute_consistency(all_verdict_maps)
    avg_distribution = _average_distribution_coverage(run_details)

    passed = (
        avg_recall >= THRESHOLDS["recall"]
        and avg_precision >= THRESHOLDS["precision"]
        and consistency >= THRESHOLDS["consistency"]
        and avg_distribution >= THRESHOLDS["distribution_coverage"]
    )

    return EvalReport(
        timestamp=datetime.now(UTC).isoformat(),
        config={"runs": num_runs, "budget": budget},
        metrics=EvalMetrics(
            recall=avg_recall,
            precision=avg_precision,
            consistency=consistency,
            distribution_coverage=avg_distribution,
        ),
        thresholds=THRESHOLDS,
        passed=passed,
        runs=run_details,
        consistency_details=consistency_details,
    )


def _average_distribution_coverage(run_details: list[RunDetail]) -> float:
    all_coverages = [dist.coverage for run in run_details for dist in run.distribution.values()]
    if not all_coverages:
        return 0.0
    return sum(all_coverages) / len(all_coverages)


def _print_summary(report: EvalReport, report_path: str) -> None:
    metrics = report.metrics
    thresholds = report.thresholds
    print("\n--- Results ---")
    _print_metric_line("Recall", metrics.recall, thresholds["recall"])
    _print_metric_line("Precision", metrics.precision, thresholds["precision"])
    _print_metric_line("Consistency", metrics.consistency, thresholds["consistency"])
    dist_threshold = thresholds["distribution_coverage"]
    _print_metric_line("Distribution", metrics.distribution_coverage, dist_threshold)
    print(f"\nReport written to {report_path}")


def _print_metric_line(name: str, value: float, threshold: float) -> None:
    status = "PASS" if value >= threshold else "FAIL"
    print(f"{name + ':':<14} {value:.2f} (threshold: {threshold:.2f}) {status}")


def _print_run_result(run_detail: RunDetail) -> None:
    for tool_name, dist in run_detail.distribution.items():
        total_cases = sum(v.case_count for v in run_detail.verdicts.get(tool_name, {}).values())
        print(f"  {tool_name}: {total_cases} cases, {dist.covered} categories covered")
    print(f"  Recall: {run_detail.recall:.2f} | Precision: {run_detail.precision:.2f}")


if __name__ == "__main__":
    main()
