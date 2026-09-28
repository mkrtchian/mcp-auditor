import argparse
import asyncio
import sys
import traceback
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from evals import eval_display as display
from evals.baseline import Baseline, load_baseline, write_baseline
from evals.cell_grid import GateGrid, RunAgainstBaseline, cell_grid, outcome_rows
from evals.concurrency import bounded, positive_int
from evals.eval_report import EvalReport
from evals.eval_runs import AnnouncedAudit, run_all
from evals.eval_session import (
    BASELINE_PATH,
    DEFAULT_BUDGET,
    DEFAULT_CONCURRENCY,
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
    models_for,
)
from evals.judging import RunsOutcome, judge_runs
from evals.metrics import SessionThrottles, VerdictMap, aggregate_verdicts
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
    result = asyncio.run(run_evals(session, options.concurrency))

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
        "--concurrency",
        type=positive_int,
        default=DEFAULT_CONCURRENCY,
        help="Audits in flight at once, runs and replays alike; 1 runs them one after the other.",
    )
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
    return EvalOptions(
        runs=args.runs,
        budget=args.budget,
        report=args.report,
        record_baseline=args.record_baseline,
        ungated=args.ungated,
        concurrency=args.concurrency,
    )


async def run_evals(session: EvalSession, concurrency: int) -> EvalRunResult:
    throttles = SessionThrottles()
    audit = _announced_audit(session, concurrency, throttles)
    outcome = await run_all(audit, session.conditions.runs)
    if not outcome.details:
        raise Refused("All runs failed.", ["no run completed: nothing to judge"])

    metrics, consistency_details = outcome.metrics()
    replayer = Replayer(
        audit=_replay_audit(audit),
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
            "concurrency": concurrency,
            "throttled_requests": throttles.requests,
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


def _announced_audit(
    session: EvalSession, concurrency: int, throttles: SessionThrottles
) -> AnnouncedAudit:
    """One bound shared by every audit of the session, runs and replays alike."""
    models = models_for(session.settings)

    async def audit(honeypot: HoneypotConfig, announcement: str | None) -> AuditReport:
        if announcement:
            display.console.print(announcement)
        report = await audit_honeypot(models, honeypot, session.conditions.budget)
        throttled = throttles.count(report)
        if throttled > 0:
            display.console.print(
                f"[yellow]{honeypot.name} was throttled {throttled} time(s)"
                " by the model provider (HTTP 429)[/yellow]"
            )
        return report

    return bounded(audit, concurrency)


def _replay_audit(audit: AnnouncedAudit) -> ReplayAudit:
    async def replay(honeypot: HoneypotConfig) -> VerdictMap:
        return aggregate_verdicts(await audit(honeypot, None))

    return replay


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
