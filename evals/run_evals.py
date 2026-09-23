import argparse
import asyncio
import os
import sys
import traceback
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from rich.progress import Progress, TaskID

from evals import eval_display as display
from evals.baseline import write_baseline
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
    open_session,
    read_tree,
    tree_drift,
)
from evals.export import export_judged_cases
from evals.gate import (
    LEGACY_THRESHOLDS,
    Cell,
    Observation,
    compare,
    metric_deltas,
    metric_resolutions,
    observe,
)
from evals.gate_verdict import GateInput, GateMode, GateResult, GateVerdict, judge_gate
from evals.honeypots import (
    HONEYPOTS,
    MERGED_GROUND_TRUTH,
    TOOL_COUNT,
    HoneypotConfig,
    audit_honeypot,
)
from evals.metrics import (
    ConsistencyDetail,
    EvalMetrics,
    RunDetail,
    VerdictMap,
    aggregate_verdicts,
    average_distribution_coverage,
    build_run_detail,
    compute_consistency,
)
from evals.recording import Recording, RecordingRefused, decide_recording, gated_set_changes
from evals.replay import ReplayAudit, Replayer
from mcp_auditor.domain.models import AuditReport, TokenUsage, ToolReport

DEFAULT_REPORT_PATH = "output/eval_report.json"

EXIT_CODES = {
    GateVerdict.GREEN: 0,
    GateVerdict.RED: 1,
    GateVerdict.NOT_COMPARABLE: NOT_COMPARABLE_EXIT,
}


@dataclass
class RunsOutcome:
    details: list[RunDetail] = field(default_factory=list[RunDetail])
    verdict_maps: list[VerdictMap] = field(default_factory=list[VerdictMap])
    audits: list[tuple[int, AuditReport]] = field(default_factory=list[tuple[int, AuditReport]])

    def observations(self) -> list[dict[Cell, Observation]]:
        return [observe(verdicts, MERGED_GROUND_TRUTH) for verdicts in self.verdict_maps]

    def metrics(self) -> tuple[EvalMetrics, dict[str, ConsistencyDetail]]:
        consistency, consistency_details = compute_consistency(self.verdict_maps)
        metrics = EvalMetrics(
            recall=sum(run.recall for run in self.details) / len(self.details),
            precision=sum(run.precision for run in self.details) / len(self.details),
            consistency=consistency,
            distribution_coverage=average_distribution_coverage(self.details),
        )
        return metrics, consistency_details


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
        help="record evals/baselines/honeypot_e2e.json from a clean tree, to commit by hand",
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
    gate = await _judge(session, outcome, metrics)
    report = EvalReport(
        timestamp=datetime.now(UTC).isoformat(),
        config={
            "runs": session.conditions.runs,
            "budget": session.conditions.budget,
            "completed_runs": len(outcome.details),
        },
        metrics=metrics,
        thresholds=LEGACY_THRESHOLDS if gate.mode == GateMode.LEGACY_THRESHOLDS else {},
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


async def _judge(session: EvalSession, outcome: RunsOutcome, metrics: EvalMetrics) -> GateResult:
    mismatches = _incomplete_runs(session.conditions.runs, len(outcome.details))
    baseline = session.baseline
    if baseline is None:
        return judge_gate(GateInput(mode=session.mode, metrics=metrics, mismatches=mismatches))

    cells = compare(baseline.observation_runs(), outcome.observations(), MERGED_GROUND_TRUTH)
    if session.mode == GateMode.PAIRED and not mismatches:
        replayer = Replayer(
            audit=_replay_audit(session), rule=baseline.replay_rule, honeypots=HONEYPOTS
        )
        cells, mismatches = await replayer.settle_flips(cells)
    resolutions = metric_resolutions(outcome.verdict_maps, MERGED_GROUND_TRUTH, TOOL_COUNT)
    return judge_gate(
        GateInput(
            mode=session.mode,
            metrics=metrics,
            baseline_status=baseline.status,
            cells=cells,
            mismatches=mismatches,
            deltas=metric_deltas(baseline.metrics, metrics, resolutions),
        )
    )


def _replay_audit(session: EvalSession) -> ReplayAudit:
    async def audit(honeypot: HoneypotConfig) -> VerdictMap:
        report = await audit_honeypot(session.settings, honeypot, session.conditions.budget)
        return aggregate_verdicts(report)

    return audit


def _incomplete_runs(requested: int, completed: int) -> list[str]:
    if completed >= requested:
        return []
    return [f"{completed} of {requested} runs completed"]


def _record(session: EvalSession, result: EvalRunResult) -> int:
    assert session.tree is not None, "open_session reads the tree whenever it records"
    drift = tree_drift(session.tree, read_tree())
    if drift:
        raise Refused("Recording refused.", drift)
    recording = Recording(
        conditions=session.conditions,
        commit=session.tree.commit,
        recorded_at=datetime.now(UTC).isoformat(),
        runs=result.outcome.observations(),
        metrics=result.report.metrics,
        completed_all=len(result.outcome.details) == session.conditions.runs,
        ground_truth=MERGED_GROUND_TRUTH,
    )
    decision = decide_recording(session.baseline, recording, result.report.gate)
    if isinstance(decision, RecordingRefused):
        raise Refused("Recording refused.", decision.reasons)
    write_baseline(BASELINE_PATH, decision)
    changes = gated_set_changes(session.baseline, decision, MERGED_GROUND_TRUTH)
    display.print_written_recording(decision, changes, BASELINE_PATH)
    return 0


if __name__ == "__main__":
    main()
