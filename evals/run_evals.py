import argparse
import asyncio
import os
import sys
import traceback
from collections.abc import Awaitable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from langchain_core.tracers.context import collect_runs
from pydantic import ValidationError
from rich.progress import Progress, TaskID

from evals import eval_display as display
from evals.baseline import Baseline, load_baseline, write_baseline
from evals.cell_grid import GateGrid, RunAgainstBaseline, cell_grid, outcome_rows
from evals.eval_report import EvalReport
from evals.eval_session import (
    BASELINE_PATH,
    DEFAULT_BUDGET,
    DEFAULT_RUNS,
    RECORDING_REFUSED,
    EvalOptions,
    EvalSession,
    Refused,
    TreeState,
    baseline_changed,
    open_session,
    read_tree,
    tree_drift,
)
from evals.export import export_judged_cases
from evals.gate_verdict import GateMode, GateVerdict
from evals.honeypots import (
    HONEYPOTS,
    MERGED_GROUND_TRUTH,
    HoneypotConfig,
    audit_honeypot,
    audit_honeypots,
    models_for,
)
from evals.judging import RunsOutcome, judge_runs
from evals.metrics import RunDetail, VerdictMap, aggregate_verdicts, build_run_detail
from evals.recording import Recording, RecordingRefused, decide_recording, gated_set_changes
from evals.replay import ReplayAudit, Replayer
from mcp_auditor.domain.models import AuditReport

DEFAULT_REPORT_PATH = "output/eval_report.json"
NOT_COMPARABLE_EXIT = 3
CRASHED_EXIT = 4

EXIT_CODES = {
    GateVerdict.GREEN: 0,
    GateVerdict.RED: 1,
    GateVerdict.NOT_COMPARABLE: NOT_COMPARABLE_EXIT,
}


@dataclass(frozen=True)
class EvalRunResult:
    report: EvalReport
    outcome: RunsOutcome


@dataclass(frozen=True)
class CompletedRun:
    verdicts: VerdictMap
    report: AuditReport
    trace_ids: list[UUID]


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
    display.print_summary(result.report, options.report, _gate_grid(session.baseline, result))

    if session.tree is not None:
        return _record(session, session.tree, result)
    return EXIT_CODES[result.report.gate.verdict]


def _gate_grid(baseline: Baseline | None, result: EvalRunResult) -> GateGrid | None:
    if baseline is None:
        return None
    gate = result.report.gate
    run = RunAgainstBaseline(comparisons=gate.cells, runs=result.outcome.observations())
    baseline_runs = baseline.observation_runs()
    paired = gate.mode == GateMode.PAIRED
    return GateGrid(
        title=f"Cells against the confirmed baseline ({len(baseline.runs)} runs)",
        sections=cell_grid(HONEYPOTS, baseline_runs, run) if paired else [],
        outcomes=outcome_rows(MERGED_GROUND_TRUTH, baseline_runs, run),
    )


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
        help=(
            "gate on the floors alone (recall: one detection per run, precision and"
            " distribution coverage: 0.50), at any conditions, with no baseline (never in CI)"
        ),
    )
    args = parser.parse_args()
    return EvalOptions(args.runs, args.budget, args.report, args.record_baseline, args.ungated)


async def run_evals(session: EvalSession) -> EvalRunResult:
    outcome = await _run_all(session)
    if not outcome.details:
        raise Refused("All runs failed.", ["no run completed: nothing to judge"])

    metrics, consistency_details = outcome.metrics()
    replayer = Replayer(
        audit=_replay_audit(session),
        honeypots=HONEYPOTS,
        announce=_announce_replay,
        warn=_warn_replay,
    )
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
                completed = await _run_one_eval(session, progress, task)
            except Exception:
                progress.console.print(f"[yellow]Warning: run {i + 1}/{num_runs} failed:[/yellow]")
                traceback.print_exc(file=sys.stderr)
                progress.advance(task, advance=len(HONEYPOTS))
                continue

            run_detail = build_run_detail(
                i, completed.verdicts, completed.report, MERGED_GROUND_TRUTH
            )
            _post_langsmith_feedback(run_detail, completed.trace_ids)
            outcome.details.append(run_detail)
            outcome.verdict_maps.append(completed.verdicts)
            outcome.audits.append((i, completed.report))
            display.print_run_result(run_detail, progress)
    return outcome


async def _run_one_eval(session: EvalSession, progress: Progress, task: TaskID) -> CompletedRun:
    trace_ids: list[UUID] = []

    async def audit(honeypot: HoneypotConfig) -> AuditReport:
        progress.console.print(f"  Auditing [bold]{honeypot.name}[/bold]...")
        report = await _traced(
            audit_honeypot(models_for(session.settings), honeypot, session.conditions.budget),
            trace_ids,
        )
        progress.advance(task)
        return report

    verdicts, report = await audit_honeypots(audit)
    return CompletedRun(verdicts, report, trace_ids)


async def _traced(audit: Awaitable[AuditReport], trace_ids: list[UUID]) -> AuditReport:
    if not _tracing_enabled():
        return await audit
    with collect_runs() as collector:
        report = await audit
    if collector.traced_runs:
        trace_ids.append(collector.traced_runs[0].id)
    return report


def _tracing_enabled() -> bool:
    return bool(os.environ.get("LANGSMITH_TRACING") or os.environ.get("LANGCHAIN_TRACING_V2"))


def _post_langsmith_feedback(run_detail: RunDetail, trace_ids: list[UUID]) -> None:
    if not _tracing_enabled():
        return
    try:
        from langsmith import Client  # type: ignore[import-untyped]

        client = Client()
        for trace_id in trace_ids:
            client.create_feedback(trace_id, key="recall", score=run_detail.recall)  # pyright: ignore[reportUnknownMemberType]
            client.create_feedback(trace_id, key="precision", score=run_detail.precision)  # pyright: ignore[reportUnknownMemberType]
    except Exception:
        pass  # Best-effort: don't fail evals because of LangSmith


def _replay_audit(session: EvalSession) -> ReplayAudit:
    async def audit(honeypot: HoneypotConfig) -> VerdictMap:
        report = await audit_honeypot(
            models_for(session.settings), honeypot, session.conditions.budget
        )
        return aggregate_verdicts(report)

    return audit


def _announce_replay(message: str) -> None:
    display.console.print(message, markup=False, highlight=False)


def _warn_replay(message: str) -> None:
    print(message, file=sys.stderr, end="")


def _record(session: EvalSession, tree: TreeState, result: EvalRunResult) -> int:
    drift = _recording_drift(session, tree)
    if drift:
        raise Refused(RECORDING_REFUSED, drift)
    recording = Recording(
        conditions=session.conditions,
        commit=tree.commit,
        recorded_at=datetime.now(UTC).isoformat(),
        runs=result.outcome.observations(),
        metrics=result.report.metrics,
        completed_all=result.outcome.completed_all(session.conditions.runs),
        protected=result.outcome.protected(),
        ground_truth=MERGED_GROUND_TRUTH,
    )
    decision = decide_recording(session.baseline, recording, result.report.gate)
    if isinstance(decision, RecordingRefused):
        raise Refused(RECORDING_REFUSED, decision.reasons)
    write_baseline(BASELINE_PATH, decision)
    changes = gated_set_changes(session.baseline, decision, MERGED_GROUND_TRUTH)
    display.print_recorded_grid(
        f"Cells of the {decision.status} baseline ({len(decision.runs)} runs)",
        cell_grid(HONEYPOTS, decision.observation_runs()),
    )
    display.print_written_recording(decision, changes, BASELINE_PATH)
    return 0


def _recording_drift(session: EvalSession, tree: TreeState) -> list[str]:
    try:
        reloaded = load_baseline(BASELINE_PATH)
    except ValidationError as error:
        reason = f"{BASELINE_PATH} is not a valid baseline: {error}"
        raise Refused(RECORDING_REFUSED, [reason]) from error
    return tree_drift(tree, read_tree()) + baseline_changed(session.baseline, reloaded)


if __name__ == "__main__":
    main()
