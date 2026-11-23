import warnings

warnings.filterwarnings("ignore", message="Core Pydantic V1", category=UserWarning)

import argparse
import asyncio
import json
import traceback
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from rich.progress import Progress

from evals.cli_arguments import positive_int
from evals.declared_flips import Instrument
from evals.eval_display import console, print_refusal
from evals.eval_session import REPOSITORY_TREE, Refused, declarations_of_head, read_tree
from evals.gate_outcome import CRASHED_EXIT, NOT_COMPARABLE_EXIT
from evals.judge.baseline import JUDGE_BASELINE_PATH
from evals.judge.display import print_summary
from evals.judge.fixture import JudgeCase, load_fixture
from evals.judge.gate import DEFAULT_JUDGE_RUNS
from evals.judge.outcomes import case_outcomes
from evals.judge.report import JudgeRunFacts, build_judge_report
from evals.judge.retest import JudgeCallVerdict
from evals.judge.session import run_judge_gate
from evals.judge.session_model import JudgeHarness, JudgeOptions
from evals.session_usage import SessionThrottles, quiet_throttle_waits
from mcp_auditor.adapters.llm import create_judge_llm
from mcp_auditor.adapters.llm_throttling import one_audit
from mcp_auditor.config import load_settings
from mcp_auditor.domain.models import (
    AuditPayload,
    EvalVerdict,
    Judgment,
    ProviderUsage,
    TestCase,
    ToolDefinition,
)
from mcp_auditor.domain.ports import (
    LLMPort,
    ProviderRefusal,
    ProviderThrottled,
    UnreadableAnswer,
)
from mcp_auditor.graph.prompts import build_judge_prompt

FIXTURES_PATH = Path(__file__).resolve().parent / "fixtures" / "judge_cases.json"
DEFAULT_REPORT_PATH = "output/judge_eval_report.json"
DEFAULT_CONCURRENCY = 30


def main(argv: Sequence[str] | None = None) -> None:
    quiet_throttle_waits()
    args = parse_args(argv)
    try:
        code = _evaluate(args)
    except Refused as refusal:
        print_refusal(refusal.title, refusal.reasons)
        code = NOT_COMPARABLE_EXIT
    except Exception:
        traceback.print_exc()
        code = CRASHED_EXIT
    raise SystemExit(code)


def _evaluate(args: argparse.Namespace) -> int:
    options = _options(args)
    fixture = load_fixture(FIXTURES_PATH)
    console.print(
        f"Running judge eval ([bold]{len(fixture.cases)}[/bold] cases, {options.runs} runs)..."
    )
    with Progress(console=console) as progress:
        llm = create_judge_llm(options.settings)
        tracking = JudgeCallTracking(llm, progress, options.runs * len(fixture.cases))
        # The session is one audit: once a judgment is throttled past every retry the run is
        # not comparable, so the later judgments are not sent.
        with one_audit():
            result = asyncio.run(run_judge_gate(options, fixture, _harness(tracking)))
    facts = JudgeRunFacts(
        datetime.now(UTC).isoformat(), tracking.throttles.requests, options.concurrency
    )
    report = build_judge_report(result, fixture, facts)
    path = Path(args.report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.model_dump(mode="json"), indent=2))
    print_summary(result, report, path, case_outcomes(result, fixture))
    return result.exit_code


def _options(args: argparse.Namespace) -> JudgeOptions:
    return JudgeOptions(
        settings=load_settings(),
        runs=args.runs,
        record_baseline=args.record_baseline,
        no_baseline=args.no_baseline,
        concurrency=args.concurrency,
    )


def _harness(tracking: "JudgeCallTracking") -> JudgeHarness:
    return JudgeHarness(
        judge=tracking.judge,
        baseline_path=JUDGE_BASELINE_PATH,
        read_tree=read_tree,
        declarations=lambda: declarations_of_head(Instrument.JUDGE, REPOSITORY_TREE),
        clock=lambda: datetime.now(UTC),
        on_retests=tracking.on_retests,
    )


class JudgeCallTracking:
    """Advances the progress of the judge calls and counts their throttled requests, warning
    once, at the first one: at 30 calls in flight, a line per throttled call would flood. A
    judgment throttled past every retry gives no verdict and says it was throttled."""

    def __init__(self, llm: LLMPort, progress: Progress, run_calls: int) -> None:
        self.throttles = SessionThrottles()
        self._llm = llm
        self._progress = progress
        self._task = progress.add_task("Judging", total=run_calls)
        self._warned = False

    async def judge(self, case: JudgeCase) -> JudgeCallVerdict:
        try:
            verdict, usage = await judge_one_case(self._llm, case)
            answer = JudgeCallVerdict(verdict)
        except ProviderThrottled as throttled:
            answer, usage = JudgeCallVerdict(None, throttled=True), throttled.usage
        if self.throttles.count_usage(usage) > 0 and not self._warned:
            self._warned = True
            self._progress.console.print(
                "[yellow]The model provider throttled a judge call (HTTP 429),"
                " the total is in the summary.[/yellow]"
            )
        self._progress.advance(self._task)
        return answer

    def on_retests(self, count: int) -> None:
        """Called once the run calls are all done, so later calls are retests."""
        self._task = self._progress.add_task(f"Retesting {count} flipped case(s)", total=None)


async def judge_one_case(llm: LLMPort, case: JudgeCase) -> tuple[EvalVerdict | None, ProviderUsage]:
    """None when the judge gave no verdict. Any other failure propagates: caught, it would
    turn a crash into every case uncovered and a red floor."""
    try:
        judgment, usage = await llm.generate_structured(_judge_prompt(case), Judgment)
    except (UnreadableAnswer, ProviderRefusal) as error:
        return None, error.usage
    return judgment.verdict, usage


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


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the judge eval")
    parser.add_argument("--runs", type=positive_int, default=DEFAULT_JUDGE_RUNS)
    parser.add_argument("--report", type=str, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--concurrency",
        type=positive_int,
        default=DEFAULT_CONCURRENCY,
        help="Judge calls in flight at once, runs and retests alike.",
    )
    parser.add_argument(
        "--record-baseline",
        action="store_true",
        help=(
            "record evals/baselines/judge.json from a clean tree: run it twice at the"
            " same commit (unconfirmed, then confirmed), then commit it by hand"
        ),
    )
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        help=(
            "gate on the floors alone (recall: one detection per run, precision: 0.50), at any"
            " conditions, with no baseline (never in CI)"
        ),
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    main()
