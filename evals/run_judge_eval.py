import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from evals.judge_metrics import (
    CaseResult,
    JudgeMetrics,
    compute_judge_metrics,
    compute_per_category_metrics,
)
from mcp_auditor.adapters.llm import create_judge_llm
from mcp_auditor.config import load_settings
from mcp_auditor.domain.models import (
    AuditCategory,
    AuditPayload,
    EvalResult,
    EvalVerdict,
    TestCase,
    ToolDefinition,
)
from mcp_auditor.graph.prompts import build_judge_prompt

FIXTURES_PATH = Path(__file__).resolve().parent / "fixtures" / "judge_cases.json"
DEFAULT_REPORT_PATH = "evals/judge_eval_report.json"
F1_THRESHOLD = 0.90

LoadedCase = tuple[ToolDefinition, TestCase, EvalVerdict, AuditCategory]


def main() -> None:
    report = asyncio.run(run_judge_eval())
    Path(DEFAULT_REPORT_PATH).write_text(json.dumps(report, indent=2))
    _print_summary(report)


async def run_judge_eval() -> dict[str, Any]:
    settings = load_settings()
    llm = create_judge_llm(settings)
    cases = _load_cases()
    results: list[tuple[AuditCategory, CaseResult]] = []
    eval_results: list[EvalResult] = []

    print(f"Running judge eval ({len(cases)} cases)...")

    for tool, test_case, expected, category in cases:
        prompt = build_judge_prompt(tool=tool, test_case=test_case)
        eval_result = await llm.generate_structured(prompt, EvalResult)
        predicted = eval_result.verdict
        results.append((category, (predicted, expected)))
        eval_results.append(eval_result)

    overall = compute_judge_metrics([cr for _, cr in results])
    per_category = compute_per_category_metrics(results)
    return _build_report(overall, per_category, results, eval_results, cases)


def _load_cases() -> list[LoadedCase]:
    raw: list[dict[str, Any]] = json.loads(FIXTURES_PATH.read_text())
    cases: list[LoadedCase] = []
    for entry in raw:
        tool = ToolDefinition(
            name=entry["tool_name"],
            description=entry["tool_description"],
            input_schema={},
        )
        payload = AuditPayload(
            tool_name=entry["tool_name"],
            category=AuditCategory(entry["category"]),
            description=entry["description"],
            arguments=entry["arguments"],
        )
        test_case = TestCase(
            payload=payload,
            response=entry.get("response"),
            error=entry.get("error"),
        )
        expected = EvalVerdict(entry["expected_verdict"])
        category = AuditCategory(entry["category"])
        cases.append((tool, test_case, expected, category))
    return cases


def _build_report(
    overall: JudgeMetrics,
    per_category: dict[AuditCategory, JudgeMetrics],
    results: list[tuple[AuditCategory, CaseResult]],
    eval_results: list[EvalResult],
    cases: list[LoadedCase],
) -> dict[str, Any]:
    per_case_details = _build_per_case_details(results, eval_results, cases)
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "metrics": {
            "precision": overall.precision,
            "recall": overall.recall,
            "f1": overall.f1,
        },
        "confusion_matrix": {
            "tp": overall.confusion.tp,
            "fp": overall.confusion.fp,
            "tn": overall.confusion.tn,
            "fn": overall.confusion.fn,
        },
        "f1_threshold": F1_THRESHOLD,
        "passed": overall.f1 >= F1_THRESHOLD,
        "per_category": {
            cat.value: {
                "precision": m.precision,
                "recall": m.recall,
                "f1": m.f1,
            }
            for cat, m in per_category.items()
        },
        "cases": per_case_details,
    }


def _build_per_case_details(
    results: list[tuple[AuditCategory, CaseResult]],
    eval_results: list[EvalResult],
    cases: list[LoadedCase],
) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    for i, (tool, _test_case, expected, category) in enumerate(cases):
        _cat, (predicted, _exp) = results[i]
        eval_result = eval_results[i]
        details.append(
            {
                "tool_name": tool.name,
                "category": category.value,
                "expected": expected.value,
                "predicted": predicted.value,
                "correct": predicted == expected,
                "justification": eval_result.justification,
            }
        )
    return details


def _print_summary(report: dict[str, Any]) -> None:
    metrics: dict[str, float] = report["metrics"]
    cm: dict[str, int] = report["confusion_matrix"]

    print("\n--- Results ---")
    print(f"{'Precision:':<13} {metrics['precision']:.2f} (threshold: n/a)")
    print(f"{'Recall:':<13} {metrics['recall']:.2f} (threshold: n/a)")
    threshold_status = "PASS" if report["passed"] else "FAIL"
    print(
        f"{'F1:':<13} {metrics['f1']:.2f} "
        f"(threshold: {report['f1_threshold']:.2f}) {threshold_status}"
    )

    print("\nConfusion matrix:")
    print(f"  TP: {cm['tp']}  FP: {cm['fp']}")
    print(f"  FN: {cm['fn']}  TN: {cm['tn']}")

    print("\nPer-category:")
    per_category: dict[str, dict[str, float]] = report["per_category"]
    for cat_name, cat_metrics in per_category.items():
        print(
            f"  {cat_name + ':':<22} "
            f"P={cat_metrics['precision']:.2f} "
            f"R={cat_metrics['recall']:.2f} "
            f"F1={cat_metrics['f1']:.2f}"
        )

    print(f"\nReport written to {DEFAULT_REPORT_PATH}")


if __name__ == "__main__":
    main()
