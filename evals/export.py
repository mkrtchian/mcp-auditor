import json
from pathlib import Path
from typing import Any

from evals.ground_truth import GroundTruth
from evals.judge.fixture import CHAIN, SINGLE_STEP, JudgeInputs
from mcp_auditor.domain.models import AttackChain, AuditReport, JudgeResult, TestCase, ToolReport


def export_judged_cases(
    runs: list[tuple[int, AuditReport]],
    ground_truth: GroundTruth,
    report_path: Path,
) -> None:
    lines = [
        {"run_index": run_index, **line, **_label(result, ground_truth)}
        for run_index, report in runs
        for tool_report in report.tool_reports
        for result, line in case_lines(tool_report) + chain_lines(tool_report)
    ]
    write_jsonl(report_path.with_name("judged_cases.jsonl"), lines)


def case_lines(tool_report: ToolReport) -> list[tuple[JudgeResult, dict[str, Any]]]:
    description = tool_report.tool.description
    return [
        (result, _judge_input(case, result, description))
        for case in tool_report.cases
        if (result := case.judge_result) is not None
    ]


def _judge_input(
    case: TestCase, result: JudgeResult, tool_description: str | None
) -> dict[str, Any]:
    inputs = JudgeInputs(
        tool_name=result.tool_name,
        tool_description=tool_description,
        category=result.category,
        description=case.payload.description,
        arguments=case.payload.arguments,
        response=case.response,
        error=case.error,
    )
    return {
        "type": SINGLE_STEP,
        **inputs.model_dump(),
        "verdict": result.verdict.value,
        "justification": result.justification,
    }


def chain_lines(tool_report: ToolReport) -> list[tuple[JudgeResult, dict[str, Any]]]:
    description = tool_report.tool.description
    return [
        (result, _chain_judge_input(chain, result, description))
        for chain in tool_report.chains
        if (result := chain.judge_result) is not None
    ]


def _chain_judge_input(
    chain: AttackChain, result: JudgeResult, tool_description: str | None
) -> dict[str, Any]:
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
        "type": CHAIN,
        "tool_name": result.tool_name,
        "tool_description": tool_description,
        "category": result.category.value,
        "goal": chain.goal.description,
        "steps": steps,
        "verdict": result.verdict.value,
        "justification": result.justification,
    }


def _label(result: JudgeResult, ground_truth: GroundTruth) -> dict[str, Any]:
    expected = ground_truth.get((result.tool_name, result.category))
    return {
        "expected_verdict": expected.value if expected else None,
        "correct": result.verdict == expected if expected else None,
    }


def write_jsonl(path: Path, lines: list[dict[str, Any]]) -> None:
    with path.open("w") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")
