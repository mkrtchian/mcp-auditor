import argparse
import asyncio
import os
import sys
import traceback
from datetime import UTC, datetime
from pathlib import Path

from evals.ground_truth import HONEYPOT_GROUND_TRUTH
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
from mcp_auditor.domain.models import AuditCategory, AuditReport
from mcp_auditor.graph.builder import build_graph

HONEYPOT_SERVER = Path(__file__).resolve().parent.parent / "tests" / "dummy_server.py"
HONEYPOT_COMMAND = "uv"
HONEYPOT_ARGS = ["run", "python", str(HONEYPOT_SERVER)]

DEFAULT_RUNS = 3
DEFAULT_BUDGET = 10
DEFAULT_REPORT_PATH = "evals/eval_report.json"

THRESHOLDS: dict[str, float] = {
    "recall": 0.80,
    "precision": 1.0,
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

    report = asyncio.run(run_evals(args.runs, args.budget))

    Path(args.report).write_text(report.model_dump_json(indent=2))
    _print_summary(report, args.report)

    if report.passed:
        print("\nAll thresholds met.")
    else:
        print("\nSome thresholds not met.")
        raise SystemExit(1)


async def run_evals(num_runs: int, budget: int) -> EvalReport:
    settings = load_settings()
    run_details: list[RunDetail] = []
    all_verdict_maps: list[VerdictMap] = []

    for i in range(num_runs):
        print(f"\nRunning eval {i + 1}/{num_runs}...")
        try:
            audit_report = await run_single_audit(settings, budget)
        except Exception:
            print(f"Warning: run {i + 1}/{num_runs} failed:")
            traceback.print_exc(file=sys.stdout)
            continue

        verdicts = aggregate_verdicts(audit_report)
        all_verdict_maps.append(verdicts)

        recall = compute_recall(verdicts, HONEYPOT_GROUND_TRUTH)
        precision = compute_precision(verdicts, HONEYPOT_GROUND_TRUTH)
        distribution = compute_distribution_coverage(audit_report, ALL_CATEGORIES)

        _post_langsmith_feedback(recall, precision, settings.langsmith_project)

        run_detail = _build_run_detail(
            i,
            verdicts,
            distribution,
            recall,
            precision,
            audit_report,
        )
        run_details.append(run_detail)
        _print_run_result(run_detail)

    if not run_details:
        print("All runs failed. Cannot produce eval report.")
        raise SystemExit(1)

    return _assemble_report(num_runs, budget, run_details, all_verdict_maps)


async def run_single_audit(settings: Settings, budget: int) -> AuditReport:
    llm = create_llm(settings)
    judge_llm = create_judge_llm(settings)
    async with StdioMCPClient.connect(HONEYPOT_COMMAND, HONEYPOT_ARGS) as mcp_client:
        graph = build_graph(llm, mcp_client, judge_llm=judge_llm)
        result = await graph.ainvoke(  # pyright: ignore[reportUnknownMemberType]
            {"target": f"{HONEYPOT_COMMAND} {' '.join(HONEYPOT_ARGS)}", "test_budget": budget}
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
    distribution: dict[str, float],
    recall: float,
    precision: float,
    audit_report: AuditReport,
) -> RunDetail:
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
        for result in tool_report.results:
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
