import argparse
import asyncio
import os
import sys
import traceback
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError
from rich.progress import Progress, TaskID

from evals import eval_display as display
from evals.baseline import load_baseline, write_baseline
from evals.eval_report import EvalReport
from evals.eval_session import (
    BASELINE_PATH,
    CRASHED_EXIT,
    DEFAULT_BUDGET,
    DEFAULT_RUNS,
    NOT_COMPARABLE_EXIT,
    EvalOptions,
    EvalSession,
    Refused,
    baseline_changed,
    open_session,
    read_tree,
    tree_drift,
)
from evals.export import export_judged_cases
from evals.gate_verdict import GateVerdict
from evals.honeypots import HONEYPOTS, MERGED_GROUND_TRUTH, HoneypotConfig, audit_honeypot
from evals.judging import RunsOutcome, judge_runs
from evals.metrics import RunDetail, VerdictMap, aggregate_verdicts, build_run_detail
from evals.recording import Recording, RecordingRefused, decide_recording, gated_set_changes
from evals.replay import ReplayAudit, Replayer
from mcp_auditor.domain.models import AuditReport, TokenUsage, ToolReport

DEFAULT_REPORT_PATH = "output/eval_report.json"

EXIT_CODES = {
    GateVerdict.GREEN: 0,
    GateVerdict.RED: 1,
    GateVerdict.NOT_COMPARABLE: NOT_COMPARABLE_EXIT,
}


@dataclass(frozen=True)
class EvalRunResult:
    report: EvalReport
    outcome: RunsOutcome


def main() -> None:
    options = _parse_args()
    try:
        code = _evaluate(options)
    except Refused as refusal:
        display.print_refusal(refusal.title, refusal.reasons)
        code = NOT_COMPARABLE_EXIT
    except Exception:
        traceback.print_exc()
        code = CRASHED_EXIT
    raise SystemExit(code)


def _evaluate(options: EvalOptions) -> int:
    session = open_session(options)
    result = asyncio.run(run_evals(session))

    report_path = Path(options.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(result.report.model_dump_json(indent=2))
    export_judged_cases(result.outcome.audits, MERGED_GROUND_TRUTH, report_path)
    display.print_summary(result.report, options.report)

    if session.record:
        return _record(session, result)
    return EXIT_CODES[result.report.gate.verdict]


def _parse_args() -> EvalOptions:
    parser = argparse.ArgumentParser(description="Run evals against the honeypots")
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    parser.add_argument("--report", type=str, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--record-baseline",
        action="store_true",
        help=(
            "record evals/baselines/honeypot_e2e.json from a clean tree: run it twice at the"
            " same commit (exploratory, then confirmed), then commit it by hand"
        ),
    )
    parser.add_argument(
        "--ungated",
        action="store_true",
        help="gate on the floors alone, at any conditions, with no baseline (never in CI)",
    )
    args = parser.parse_args()
    return EvalOptions(args.runs, args.budget, args.report, args.record_baseline, args.ungated)


async def run_evals(session: EvalSession) -> EvalRunResult:
    outcome = await _run_all(session)
    if not outcome.details:
        raise Refused("All runs failed.", ["no run completed: nothing to judge"])

    metrics, consistency_details = outcome.metrics()
    replayer = Replayer(audit=_replay_audit(session), honeypots=HONEYPOTS)
    gate = await judge_runs(session, outcome, replayer)
    report = EvalReport(
        timestamp=datetime.now(UTC).isoformat(),
        config={
            "runs": session.conditions.runs,
            "budget": session.conditions.budget,
            "completed_runs": len(outcome.details),
        },
        metrics=metrics,
        thresholds=gate.thresholds,
        passed=gate.verdict == GateVerdict.GREEN,
        gate=gate,
        runs=outcome.details,
        consistency_details=consistency_details,
    )
    return EvalRunResult(report=report, outcome=outcome)


async def _run_all(session: EvalSession) -> RunsOutcome:
    outcome = RunsOutcome()
    num_runs = session.conditions.runs
    with Progress(console=display.console) as progress:
        task = progress.add_task("Running evals", total=num_runs * len(HONEYPOTS))
        for i in range(num_runs):
            try:
                verdicts, audit_report = await _run_one_eval(session, progress, task)
            except Exception:
                progress.console.print(f"[yellow]Warning: run {i + 1}/{num_runs} failed:[/yellow]")
                traceback.print_exc(file=sys.stderr)
                progress.advance(task, advance=len(HONEYPOTS))
                continue

            run_detail = build_run_detail(i, verdicts, audit_report, MERGED_GROUND_TRUTH)
            _post_langsmith_feedback(run_detail, session.settings.langsmith_project)
            outcome.details.append(run_detail)
            outcome.verdict_maps.append(verdicts)
            outcome.audits.append((i, audit_report))
            display.print_run_result(run_detail, progress)
    return outcome


async def _run_one_eval(
    session: EvalSession, progress: Progress, task: TaskID
) -> tuple[VerdictMap, AuditReport]:
    merged_verdicts: VerdictMap = {}
    all_tool_reports: list[ToolReport] = []
    total_usage = TokenUsage()
    for honeypot in HONEYPOTS:
        progress.console.print(f"  Auditing [bold]{honeypot.name}[/bold]...")
        report = await audit_honeypot(session.settings, honeypot, session.conditions.budget)
        merged_verdicts.update(aggregate_verdicts(report))
        all_tool_reports.extend(report.tool_reports)
        total_usage = total_usage.add(report.token_usage)
        progress.advance(task)

    merged_report = AuditReport(
        target="evals", tool_reports=all_tool_reports, token_usage=total_usage
    )
    return merged_verdicts, merged_report


def _post_langsmith_feedback(run_detail: RunDetail, project_name: str) -> None:
    if not (os.environ.get("LANGSMITH_TRACING") or os.environ.get("LANGCHAIN_TRACING_V2")):
        return
    try:
        from langsmith import Client  # type: ignore[import-untyped]

        client = Client()
        runs = list(client.list_runs(project_name=project_name, limit=1))
        if not runs:
            return
        run_id = runs[0].id
        client.create_feedback(run_id, key="recall", score=run_detail.recall)  # pyright: ignore[reportUnknownMemberType]
        client.create_feedback(run_id, key="precision", score=run_detail.precision)  # pyright: ignore[reportUnknownMemberType]
    except Exception:
        pass  # Best-effort — don't fail evals because of LangSmith


def _replay_audit(session: EvalSession) -> ReplayAudit:
    async def audit(honeypot: HoneypotConfig) -> VerdictMap:
        report = await audit_honeypot(session.settings, honeypot, session.conditions.budget)
        return aggregate_verdicts(report)

    return audit


def _record(session: EvalSession, result: EvalRunResult) -> int:
    assert session.tree is not None, "open_session reads the tree whenever it records"
    drift = _recording_drift(session)
    if drift:
        raise Refused("Recording refused.", drift)
    recording = Recording(
        conditions=session.conditions,
        commit=session.tree.commit,
        recorded_at=datetime.now(UTC).isoformat(),
        runs=result.outcome.observations(),
        metrics=result.report.metrics,
        completed_all=result.outcome.completed_all(session.conditions.runs),
        ground_truth=MERGED_GROUND_TRUTH,
    )
    decision = decide_recording(session.baseline, recording, result.report.gate)
    if isinstance(decision, RecordingRefused):
        raise Refused("Recording refused.", decision.reasons)
    write_baseline(BASELINE_PATH, decision)
    changes = gated_set_changes(session.baseline, decision, MERGED_GROUND_TRUTH)
    display.print_written_recording(decision, changes, BASELINE_PATH)
    return 0


def _recording_drift(session: EvalSession) -> list[str]:
    assert session.tree is not None, "open_session reads the tree whenever it records"
    try:
        reloaded = load_baseline(BASELINE_PATH)
    except ValidationError as error:
        reason = f"{BASELINE_PATH} is not a valid baseline: {error}"
        raise Refused("Recording refused.", [reason]) from error
    return tree_drift(session.tree, read_tree()) + baseline_changed(session.baseline, reloaded)


if __name__ == "__main__":
    main()
