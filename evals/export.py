import json
from pathlib import Path
from typing import Any

from evals.ground_truth import GroundTruth
from mcp_auditor.domain.models import AttackChain, AuditReport, TestCase


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
                    if case.eval_result is None:
                        continue
                    line = _single_step_line(
                        run_index, case, tool_report.tool.description, ground_truth,
                    )
                    f.write(json.dumps(line) + "\n")
                for chain in tool_report.chains:
                    line = _chain_line(
                        run_index, chain, tool_report.tool.description, ground_truth,
                    )
                    if line:
                        f.write(json.dumps(line) + "\n")


def _single_step_line(
    run_index: int,
    case: TestCase,
    tool_description: str | None,
    ground_truth: GroundTruth,
) -> dict[str, Any]:
    result = case.eval_result
    assert result is not None
    gt_key = (result.tool_name, result.category)
    expected = ground_truth.get(gt_key)
    return {
        "run_index": run_index,
        "type": "single_step",
        "tool_name": result.tool_name,
        "tool_description": tool_description,
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


def _chain_line(
    run_index: int,
    chain: AttackChain,
    tool_description: str | None,
    ground_truth: GroundTruth,
) -> dict[str, Any] | None:
    result = chain.eval_result
    if result is None:
        return None
    gt_key = (result.tool_name, result.category)
    expected = ground_truth.get(gt_key)
    steps = [
        {
            "arguments": step.payload.arguments,
            "response": step.response,
            "error": step.error,
            "observation": step.observation,
        }
        for step in chain.steps
    ]
    return {
        "run_index": run_index,
        "type": "chain",
        "tool_name": result.tool_name,
        "tool_description": tool_description,
        "category": result.category.value,
        "goal": chain.goal.description,
        "steps": steps,
        "verdict": result.verdict.value,
        "justification": result.justification,
        "expected_verdict": expected.value if expected else None,
        "correct": result.verdict == expected if expected else None,
    }
