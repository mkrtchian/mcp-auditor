import argparse
import asyncio
import sys
import traceback
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from evals import eval_display as display
from evals.baseline import Baseline, load_baseline, write_baseline
from evals.cell_grid import GateGrid, RunAgainstBaseline, cell_grid, outcome_rows
from evals.cli_arguments import positive_int
from evals.concurrency import bounded
from evals.eval_session import (
    RECORDING_REFUSED,
    REPOSITORY_TREE,
    Refused,
    TreeState,
    baseline_changed,
    read_tree,
    tree_drift,
)
from evals.export import export_judged_cases
from evals.gate_outcome import CRASHED_EXIT, NOT_COMPARABLE_EXIT, GateMode, GateOutcome
from evals.ground_truth import parse_cell_key
from evals.honeypot.decision import RunsOutcome, decide_runs
from evals.honeypot.report import HoneypotReport
from evals.honeypot.retest import RetestAudit, Retester
from evals.honeypot.runs import AnnouncedAudit, run_all
from evals.honeypot.session import (
    BASELINE_PATH,
    DEFAULT_CONCURRENCY,
    DEFAULT_RUNS,
    DEFAULT_TEST_BUDGET,
    HoneypotOptions,
    HoneypotSession,
    open_session,
)
from evals.honeypots import (
    HONEYPOTS,
    MERGED_GROUND_TRUTH,
    HoneypotAudit,
    HoneypotConfig,
    audit_honeypot,
    models_for,
)
from evals.metrics import VerdictMap, aggregate_verdicts
from evals.recording import RecordingRefused, decide_recording, gated_set_changes
from evals.session_usage import SessionThrottles, quiet_throttle_waits, raise_if_throttled
from mcp_auditor.config import load_settings
from mcp_auditor.domain.models import AuditReport

DEFAULT_REPORT_PATH = "output/honeypot_report.json"


@dataclass(frozen=True)
class HoneypotRunResult:
    report: HoneypotReport
    outcome: RunsOutcome


def main(argv: Sequence[str] | None = None) -> None:
    quiet_throttle_waits()
    args = parse_args(argv)
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
    options = _options(args)
    session = open_session(options, REPOSITORY_TREE, BASELINE_PATH)
    result = asyncio.run(run_honeypot_suite(session, options.concurrency))

    report_path = Path(options.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(result.report.model_dump_json(indent=2))
    export_judged_cases(result.outcome.audits, MERGED_GROUND_TRUTH, report_path)
    display.print_summary(
        result.report,
        options.report,
        _gate_grid(session.baseline, result),
        session.declarations.ignored,
    )

    if session.tree is not None:
        return _record(session, session.tree, result)
    return result.report.gate.outcome.exit_code


def _options(args: argparse.Namespace) -> HoneypotOptions:
    return HoneypotOptions(
        settings=load_settings(),
        runs=args.runs,
        test_budget=args.budget,
        report=args.report,
        record_baseline=args.record_baseline,
        no_baseline=args.no_baseline,
        concurrency=args.concurrency,
    )


def _gate_grid(baseline: Baseline | None, result: HoneypotRunResult) -> GateGrid | None:
    if baseline is None:
        return None
    gate = result.report.gate
    run = RunAgainstBaseline(
        comparisons={parse_cell_key(key): comparison for key, comparison in gate.cells.items()},
        runs=result.outcome.observations(),
    )
    baseline_runs = baseline.observation_runs()
    paired = gate.mode == GateMode.PAIRED
    return GateGrid(
        title=f"Cells against the confirmed baseline ({len(baseline.runs)} runs)",
        sections=cell_grid(HONEYPOTS, baseline_runs, run) if paired else [],
        outcomes=outcome_rows(MERGED_GROUND_TRUTH, baseline_runs, run),
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the honeypot suite")
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    parser.add_argument("--budget", type=int, default=DEFAULT_TEST_BUDGET)
    parser.add_argument("--report", type=str, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--concurrency",
        type=positive_int,
        default=DEFAULT_CONCURRENCY,
        help="Audits in flight at once, runs and retests alike; 1 runs them one after the other.",
    )
    parser.add_argument(
        "--record-baseline",
        action="store_true",
        help=(
            "record evals/baselines/honeypot.json from a clean tree: run it twice at the"
            " same commit (unconfirmed, then confirmed), then commit it by hand"
        ),
    )
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        help=(
            "gate on the floors alone (recall: one detection per run, precision and"
            " distribution coverage: 0.50), at any conditions, with no baseline (never in CI)"
        ),
    )
    return parser.parse_args(argv)


async def run_honeypot_suite(session: HoneypotSession, concurrency: int) -> HoneypotRunResult:
    tree = session.tree or read_tree()
    throttles = SessionThrottles()
    audit = _announced_audit(session, concurrency, throttles)
    outcome = await run_all(audit, session.conditions.runs)
    if not outcome.runs:
        raise Refused("All runs failed.", ["no run completed: nothing to judge"])

    retester = Retester(
        audit=retest_audit(audit),
        honeypots=HONEYPOTS,
        announce=_announce_retest,
        warn=_warn_retest,
    )
    gate = await decide_runs(session.gate_basis, outcome, retester)
    report = HoneypotReport(
        timestamp=datetime.now(UTC).isoformat(),
        commit=tree.commit,
        dirty=tree.dirty,
        conditions=session.conditions,
        config={
            "runs": session.conditions.runs,
            "budget": session.conditions.budget,
            "concurrency": concurrency,
            "throttled_requests": throttles.requests,
            "completed_runs": len(outcome.runs),
        },
        metrics=outcome.metrics(),
        thresholds=gate.thresholds,
        passed=gate.outcome == GateOutcome.GREEN,
        gate=gate,
        runs=outcome.details,
        consistency_details=outcome.consistency_details(),
    )
    return HoneypotRunResult(report=report, outcome=outcome)


def _announced_audit(
    session: HoneypotSession, concurrency: int, throttles: SessionThrottles
) -> AnnouncedAudit:
    """One bound shared by every audit of the session, runs and retests alike."""
    models = models_for(session.settings)

    async def audit_one(honeypot: HoneypotConfig) -> AuditReport:
        return await audit_honeypot(models, honeypot, session.conditions.budget)

    return bounded(counted_audit(audit_one, throttles), concurrency)


def counted_audit(audit_one: HoneypotAudit, throttles: SessionThrottles) -> AnnouncedAudit:
    """A throttled audit raises once its 429s are counted, so a throttled pass is a failed pass
    and a throttled retest a failed retest, both leaving the run not comparable."""

    async def audit(honeypot: HoneypotConfig, announcement: str | None) -> AuditReport:
        if announcement:
            display.console.print(announcement)
        report = await audit_one(honeypot)
        throttled = throttles.count(report)
        if throttled > 0:
            display.console.print(
                f"[yellow]{honeypot.name} was throttled {throttled} time(s)"
                " by the model provider (HTTP 429)[/yellow]"
            )
        raise_if_throttled(report)
        return report

    return audit


def retest_audit(audit: AnnouncedAudit) -> RetestAudit:
    async def retest(honeypot: HoneypotConfig) -> VerdictMap:
        return aggregate_verdicts(await audit(honeypot, None))

    return retest


def _announce_retest(message: str) -> None:
    display.console.print(message, markup=False, highlight=False)


def _warn_retest(message: str) -> None:
    print(message, file=sys.stderr, end="")


def _record(session: HoneypotSession, tree: TreeState, result: HoneypotRunResult) -> int:
    drift = _recording_drift(session, tree)
    if drift:
        raise Refused(RECORDING_REFUSED, drift)
    recording = result.outcome.recording(
        session.conditions, tree.commit, datetime.now(UTC).isoformat()
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


def _recording_drift(session: HoneypotSession, tree: TreeState) -> list[str]:
    try:
        reloaded = load_baseline(BASELINE_PATH)
    except ValidationError as error:
        reason = f"{BASELINE_PATH} is not a valid baseline: {error}"
        raise Refused(RECORDING_REFUSED, [reason]) from error
    return tree_drift(tree, read_tree()) + baseline_changed(session.baseline, reloaded)


if __name__ == "__main__":
    main()
