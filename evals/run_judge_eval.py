import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from evals.judge_metrics import (
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
from mcp_auditor.domain.ports import LLMPort
from mcp_auditor.graph.prompts import build_judge_prompt

FIXTURES_PATH = Path(__file__).resolve().parent / "fixtures" / "judge_cases.json"
DEFAULT_REPORT_PATH = "evals/judge_eval_report.json"
F1_THRESHOLD = 0.90

LoadedCase = tuple[ToolDefinition, TestCase, EvalVerdict, AuditCategory]


@dataclass(frozen=True)
class JudgedCase:
    tool: ToolDefinition
    category: AuditCategory
    expected: EvalVerdict
    predicted: EvalVerdict
    justification: str


def main() -> None:
    report = asyncio.run(run_judge_eval())
    Path(DEFAULT_REPORT_PATH).write_text(json.dumps(report, indent=2))
    _print_summary(report)


async def run_judge_eval() -> dict[str, Any]:
    settings = load_settings()
    llm = create_judge_llm(settings)
    loaded_cases = _load_cases()

    print(f"Running judge eval ({len(loaded_cases)} cases)...")

    judged = await _judge_all_cases(llm, loaded_cases)
    categorized = [(j.category, (j.predicted, j.expected)) for j in judged]
    overall = compute_judge_metrics([cr for _, cr in categorized])
    per_category = compute_per_category_metrics(categorized)
    return _build_report(overall, per_category, judged)


async def _judge_all_cases(llm: LLMPort, cases: list[LoadedCase]) -> list[JudgedCase]:
    judged: list[JudgedCase] = []
    for i, (tool, test_case, expected, category) in enumerate(cases, 1):
        print(f"  [{i}/{len(cases)}] {tool.name} / {category}...", flush=True)
        prompt = build_judge_prompt(tool=tool, test_case=test_case)
        eval_result = await llm.generate_structured(prompt, EvalResult)
        judged.append(
            JudgedCase(
                tool=tool,
                category=category,
                expected=expected,
                predicted=eval_result.verdict,
                justification=eval_result.justification,
            )
        )
    return judged


def _load_cases() -> list[LoadedCase]:
    raw: list[dict[str, Any]] = json.loads(FIXTURES_PATH.read_text())
    return [_parse_case(entry) for entry in raw]


def _parse_case(entry: dict[str, Any]) -> LoadedCase:
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
    return (tool, test_case, expected, category)


def _build_report(
    overall: JudgeMetrics,
    per_category: dict[AuditCategory, JudgeMetrics],
    judged_cases: list[JudgedCase],
) -> dict[str, Any]:
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
        "cases": [_case_detail(j) for j in judged_cases],
    }


def _case_detail(judged: JudgedCase) -> dict[str, Any]:
    return {
        "tool_name": judged.tool.name,
        "category": judged.category.value,
        "expected": judged.expected.value,
        "predicted": judged.predicted.value,
        "correct": judged.predicted == judged.expected,
        "justification": judged.justification,
    }


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
