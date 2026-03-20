import json
from pathlib import Path

from evals.ground_truth import GroundTruth
from mcp_auditor.domain.models import AuditReport


def export_judged_cases(
    runs: list[tuple[int, AuditReport]],
    ground_truth: GroundTruth,
    report_path: Path,
) -> None:
    export_path = report_path.with_name("judged_cases.jsonl")
    with export_path.open("w") as f:
        for run_index, report in runs:
            for tool_report in report.tool_reports:
                for case in tool_report.cases:
                    result = case.eval_result
                    if result is None:
                        continue
                    gt_key = (result.tool_name, result.category)
                    expected = ground_truth.get(gt_key)
                    line = {
                        "run_index": run_index,
                        "tool_name": result.tool_name,
                        "tool_description": tool_report.tool.description,
                        "category": result.category.value,
                        "description": case.payload.description,
                        "arguments": case.payload.arguments,
                        "response": case.response,
                        "error": case.error,
                        "verdict": result.verdict.value,
                        "justification": result.justification,
                        "expected_verdict": expected.value if expected else None,
                        "correct": result.verdict == expected if expected else None,
                    }
                    f.write(json.dumps(line) + "\n")
