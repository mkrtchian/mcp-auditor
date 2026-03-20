import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table

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

console = Console()


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

    console.print(f"Running judge eval ([bold]{len(loaded_cases)}[/bold] cases)...")

    judged = await _judge_all_cases(llm, loaded_cases)
    categorized = [(j.category, (j.predicted, j.expected)) for j in judged]
    overall = compute_judge_metrics([cr for _, cr in categorized])
    per_category = compute_per_category_metrics(categorized)
    return _build_report(overall, per_category, judged)


async def _judge_all_cases(llm: LLMPort, cases: list[LoadedCase]) -> list[JudgedCase]:
    judged: list[JudgedCase] = []
    with Progress(console=console) as progress:
        task = progress.add_task("Judging cases", total=len(cases))
        for tool, test_case, expected, category in cases:
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
            progress.advance(task)
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
    per_category: dict[str, dict[str, float]] = report["per_category"]

    threshold_status = _pass_fail_markup(report["passed"])
    f1_line = (
        f"F1: {metrics['f1']:.2f} (threshold: {report['f1_threshold']:.2f}) {threshold_status}"
    )
    pr_line = f"Precision: {metrics['precision']:.2f}  Recall: {metrics['recall']:.2f}"
    cm_text = (
        f"Confusion Matrix:\n  TP: {cm['tp']}  FP: {cm['fp']}\n  FN: {cm['fn']}  TN: {cm['tn']}"
    )

    category_table = Table(show_header=True, header_style="bold")
    category_table.add_column("Category")
    category_table.add_column("P", justify="right")
    category_table.add_column("R", justify="right")
    category_table.add_column("F1", justify="right")
    for cat_name, cat_metrics in per_category.items():
        category_table.add_row(
            cat_name,
            f"{cat_metrics['precision']:.2f}",
            f"{cat_metrics['recall']:.2f}",
            f"{cat_metrics['f1']:.2f}",
        )

    panel_content = f"{f1_line}\n{pr_line}\n\n{cm_text}\n\nPer-category:\n"
    panel = Panel(panel_content, title="Judge Eval Results")
    console.print(panel)
    console.print(category_table)
    console.print(f"Report written to {DEFAULT_REPORT_PATH}")


def _pass_fail_markup(passed: bool) -> str:
    return "[green]PASS[/green]" if passed else "[red]FAIL[/red]"


if __name__ == "__main__":
    main()
