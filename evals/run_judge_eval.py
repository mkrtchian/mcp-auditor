import warnings

warnings.filterwarnings("ignore", message="Core Pydantic V1", category=UserWarning)

import argparse
import asyncio
import json
import traceback
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from evals import judge_display as display
from evals.concurrency import positive_int
from evals.declared_flips import Suite
from evals.eval_session import Refused, declarations_of_head, read_tree
from evals.gate import Observation
from evals.judge_baseline import JUDGE_BASELINE_PATH
from evals.judge_fixture import JudgeCase, JudgeFixture, ground_truth_of, load_fixture
from evals.judge_gate import DEFAULT_JUDGE_RUNS
from evals.judge_metrics import (
    CaseResult,
    JudgeMetrics,
    compute_judge_metrics,
    compute_per_category_metrics,
)
from evals.judge_session import (
    NOT_COMPARABLE_EXIT,
    JudgeHarness,
    JudgeOptions,
    JudgeSessionResult,
    run_judge_gate,
)
from mcp_auditor.adapters.llm import create_judge_llm
from mcp_auditor.config import load_settings
from mcp_auditor.domain.models import (
    AuditPayload,
    EvalVerdict,
    Judgment,
    TestCase,
    ToolDefinition,
)
from mcp_auditor.domain.ports import LLMPort, ProviderRefusal, UnparseableOutput
from mcp_auditor.graph.prompts import build_judge_prompt

FIXTURES_PATH = Path(__file__).resolve().parent / "fixtures" / "judge_cases.json"
DEFAULT_REPORT_PATH = "output/judge_eval_report.json"
DEFAULT_CONCURRENCY = 15
CRASHED_EXIT = 4


def main() -> None:
    args = _parse_args()
    try:
        code = _evaluate(args)
    except Refused as refusal:
        display.print_refusal(refusal.title, refusal.reasons)
        code = NOT_COMPARABLE_EXIT
    except Exception:
        traceback.print_exc()
        code = CRASHED_EXIT
    raise SystemExit(code)


def _evaluate(args: argparse.Namespace) -> int:
    options = JudgeOptions(
        settings=load_settings(),
        runs=args.runs,
        record_baseline=args.record_baseline,
        ungated=args.ungated,
        concurrency=args.concurrency,
    )
    fixture = load_fixture(FIXTURES_PATH)
    llm = create_judge_llm(options.settings)

    async def judge(case: JudgeCase) -> EvalVerdict | None:
        return await judge_one_case(llm, case)

    harness = JudgeHarness(
        judge=judge,
        baseline_path=JUDGE_BASELINE_PATH,
        read_tree=read_tree,
        declarations=lambda: declarations_of_head(Suite.JUDGE),
        clock=lambda: datetime.now(UTC),
    )
    display.console.print(
        f"Running judge eval ([bold]{len(fixture.cases)}[/bold] cases, {options.runs} runs)..."
    )
    result = asyncio.run(run_judge_gate(options, fixture, harness))
    report = _build_report(result, fixture)
    path = Path(args.report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    display.print_summary(result, report, path)
    return result.exit_code


async def judge_one_case(llm: LLMPort, case: JudgeCase) -> EvalVerdict | None:
    """None when the judge gave no verdict. Any other failure propagates: caught, it would
    turn a crash into every case uncovered and a red floor."""
    try:
        judgment, _ = await llm.generate_structured(_judge_prompt(case), Judgment)
    except (UnparseableOutput, ProviderRefusal):
        return None
    return judgment.verdict


def _judge_prompt(case: JudgeCase) -> str:
    inputs = case.inputs
    tool = ToolDefinition(
        name=inputs.tool_name, description=inputs.tool_description, input_schema={}
    )
    payload = AuditPayload(
        category=inputs.category, description=inputs.description, arguments=inputs.arguments
    )
    test_case = TestCase(payload=payload, response=inputs.response, error=inputs.error)
    return build_judge_prompt(tool=tool, test_case=test_case)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the judge isolation eval")
    parser.add_argument("--runs", type=positive_int, default=DEFAULT_JUDGE_RUNS)
    parser.add_argument("--report", type=str, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--concurrency",
        type=positive_int,
        default=DEFAULT_CONCURRENCY,
        help="Judge calls in flight at once, runs and replays alike.",
    )
    parser.add_argument(
        "--record-baseline",
        action="store_true",
        help=(
            "record evals/baselines/judge_isolation.json from a clean tree: run it twice at the"
            " same commit (exploratory, then confirmed), then commit it by hand"
        ),
    )
    parser.add_argument(
        "--ungated",
        action="store_true",
        help=(
            "gate on the floors alone (recall: one detection per run, precision: 0.50), at any"
            " conditions, with no baseline (never in CI)"
        ),
    )
    return parser.parse_args()


def _build_report(result: JudgeSessionResult, fixture: JudgeFixture) -> dict[str, Any]:
    """Precision, recall and F1 are diagnostics: the gate is the case comparison."""
    scored = [_scored_cases(run, fixture) for run in result.runs]
    categories = {case.id: case.inputs.category for case in fixture.cases}
    pooled = [(categories[case], pair) for run in scored for case, pair in run]
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "conditions": result.conditions.model_dump(mode="json"),
        "inputs_fingerprint": result.conditions.inputs_fingerprint,
        "per_run": [_metrics_json(compute_judge_metrics([p for _, p in run])) for run in scored],
        "per_category": {
            category.value: _metrics_json(metrics)
            for category, metrics in compute_per_category_metrics(pooled).items()
        },
        "gate": result.gate.model_dump(mode="json"),
        "runs": [{case: seen.value for case, seen in run.items()} for run in result.runs],
        "recorded": result.written.status.value if result.written else None,
        "recording_refused": result.recording_refused,
    }


def _scored_cases(
    run: dict[str, Observation], fixture: JudgeFixture
) -> list[tuple[str, CaseResult]]:
    """The labeled cases the judge gave a verdict on, uncovered ones left out."""
    return [
        (case, (EvalVerdict(run[case].value), expected))
        for case, expected in ground_truth_of(fixture).items()
        if run[case] != Observation.UNCOVERED
    ]


def _metrics_json(metrics: JudgeMetrics) -> dict[str, Any]:
    confusion = metrics.confusion
    return {
        "precision": metrics.precision,
        "recall": metrics.recall,
        "f1": metrics.f1,
        "confusion_matrix": {
            "tp": confusion.tp,
            "fp": confusion.fp,
            "tn": confusion.tn,
            "fn": confusion.fn,
        },
    }


if __name__ == "__main__":
    main()
