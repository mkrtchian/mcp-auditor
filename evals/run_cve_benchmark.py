import argparse
import asyncio
import json
import sys
import traceback
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from rich.progress import Progress

from evals import eval_display as display
from evals.audit_progress import AuditProgress
from evals.concurrency import bounded, positive_int
from evals.cve_audit import audit_target
from evals.cve_baseline import (
    CVE_BASELINE_DIRECTORY,
    CVERunConditions,
    image_ids,
    run_conditions,
)
from evals.cve_calibration import calibrate_all, calibrate_one, check_target
from evals.cve_console import print_cve_summary
from evals.cve_costs import CostPricing
from evals.cve_layout_check import confirm_admission
from evals.cve_measurement import (
    MeasurementSettings,
    add_measurement_flags,
    cost_pricing,
    measurement_from,
    measurement_refusal,
    run_overrides,
)
from evals.cve_oracle import (
    CVEBenchmarkReport,
    CVEResult,
    not_run,
    out_of_scope_results,
    render_markdown,
    result_for,
)
from evals.cve_places import HOLDOUT_PLACES, Places, load_places
from evals.cve_preflight import preflight_ok
from evals.cve_recording_console import print_recording
from evals.cve_session import CVESessionResult, run_gated
from evals.cve_session_model import CVEHarness, CVEOptions
from evals.cve_survey import survey_all, survey_one
from evals.cve_targets import CVE_TARGETS, OUT_OF_SCOPE_CVES, CVETarget, OutOfScopeCVE
from evals.eval_display import console
from evals.eval_session import RECORDING_REFUSED, Refused, read_tree
from evals.export import export_cve_judged_cases
from evals.holdout_conditions import CONDITIONS_PATH, load_conditions
from evals.metrics import SessionThrottles, quiet_throttle_waits
from mcp_auditor.config import load_settings

CVE_RUNS = 3
CVE_TEST_BUDGET = 10
CVE_CONCURRENCY = 6
DEFAULT_REPORT_PATH = "output/cve_report.json"
NOT_COMPARABLE_EXIT = 3
CRASHED_EXIT = 4


def main() -> None:
    quiet_throttle_waits()
    args = _parse_args()
    graded = _filter_by_cve(CVE_TARGETS, args.cve)
    tracked = _filter_by_cve(OUT_OF_SCOPE_CVES, args.cve)
    _reject_unknown_cves(args.cve, {t.cve_id for t in (*graded, *tracked)})
    refusal = _flag_refusal(args)
    if refusal:
        display.print_refusal(RECORDING_REFUSED if args.record_baseline else "Refused.", [refusal])
        sys.exit(NOT_COMPARABLE_EXIT)

    # Says nothing of detection nor of the fixtures, so a crash in every mode.
    if not preflight_ok():
        sys.exit(CRASHED_EXIT)

    try:
        code = asyncio.run(_run(args, graded, tracked))
    except Refused as refused:
        display.print_refusal(refused.title, refused.reasons)
        code = NOT_COMPARABLE_EXIT
    except Exception:
        traceback.print_exc()
        code = CRASHED_EXIT
    sys.exit(code)


async def _run(
    args: argparse.Namespace, graded: list[CVETarget], tracked: list[OutOfScopeCVE]
) -> int:
    # Calibration and the survey run under the same crash handler as the graded path, so a
    # configuration error out of either exits 4, not Python's exit 1, which reads as a dead fixture.
    places = load_places(HOLDOUT_PLACES)
    if args.survey:
        await survey_all(graded, bounded(lambda t: survey_one(t, places), args.concurrency))
        return 0
    if args.calibrate:
        # ADR 031 admission, confirmed before a draw: Docker-dependent, deterministic, run only
        # under the maintainer paths (calibrate and record-baseline), never on a gated comparison
        # and not beside the synchronous preflight (no container exists there). The rule runs the
        # layout check before the exploits (holdout-rule.md:159), so it reports its break first.
        admission_failures = await confirm_admission(graded, places, ci=args.ci)
        all_live = await calibrate_all(
            graded, bounded(lambda t: calibrate_one(t, places), args.concurrency), ci=args.ci
        )
        return 0 if all_live and not admission_failures else 1
    # A kept layout place without a route is a misconfigured fixture: refuse before recording.
    if args.record_baseline and await confirm_admission(graded, places, ci=args.ci):
        return 1
    return await _run_graded(args, graded, tracked, places)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the CVE validation benchmark")
    parser.add_argument("--runs", type=int, default=CVE_RUNS)
    parser.add_argument("--budget", type=int, default=CVE_TEST_BUDGET)
    parser.add_argument("--report", type=str, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--concurrency",
        type=positive_int,
        default=CVE_CONCURRENCY,
        help="Audits (or calibrations) in flight at once; 1 runs them one after the other.",
    )
    parser.add_argument(
        "--calibrate",
        action="store_true",
        help=(
            "No-LLM exploits and benign call per target; confirms each fixture is live on "
            "the vulnerable version and fixed on the patched one."
        ),
    )
    parser.add_argument(
        "--survey",
        action="store_true",
        help="No-LLM survey: plant every in-scope candidate and report what each surfaces.",
    )
    parser.add_argument(
        "--cve",
        action="append",
        metavar="CVE-ID",
        help="Run only these CVE ids (repeatable); default: all.",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Skip fixtures marked CI-unstable (ci_skip_reason); for the CI calibration gate.",
    )
    parser.add_argument(
        "--record-baseline",
        action="store_true",
        help=(
            "Record one file per target in evals/baselines/cve/ from a clean tree: run it twice "
            "at one commit on the local images (exploratory, then confirmed), commit by hand."
        ),
    )
    parser.add_argument(
        "--ungated",
        action="store_true",
        help="Run and report without comparing to evals/baselines/cve/ (exit 0).",
    )
    add_measurement_flags(parser)
    return parser.parse_args()


def _flag_refusal(args: argparse.Namespace) -> str | None:
    if args.survey and (args.calibrate or args.record_baseline or args.ungated):
        return "--survey runs no audit: it neither records nor gates"
    if args.calibrate and (args.record_baseline or args.ungated):
        return "--calibrate runs no audit: it neither records nor gates"
    if args.record_baseline and args.ungated:
        return "--record-baseline cannot run --ungated: a baseline records the conditions it gates"
    return measurement_refusal(args)


async def _run_graded(
    args: argparse.Namespace,
    graded: list[CVETarget],
    tracked: list[OutOfScopeCVE],
    places: Places,
) -> int:
    tree = read_tree()
    conditions = run_conditions(load_settings(), args.runs, args.budget)
    measurement = measurement_from(args)
    pricing = _cost_pricing(args.ungated, measurement, conditions)
    options = CVEOptions(graded, conditions, args.ungated, args.record_baseline)
    throttles = SessionThrottles()
    with Progress(console=console) as bar:
        tracking = _Tracking(throttles, AuditProgress(bar))
        session = await run_gated(options, _harness(args, places, tracking))
    results = [_result(target, session, args.budget) for target in graded]
    results.extend(out_of_scope_results(tracked))
    report = CVEBenchmarkReport(
        conditions=conditions,
        concurrency=args.concurrency,
        throttled_requests=throttles.requests,
        provider_usage=throttles.usage,
        commit=tree.commit,
        dirty=tree.dirty,
        results=results,
        gate=session.gate,
        recording_refused=session.recording_refused,
        measurement=measurement,
        costs=[] if pricing is None else pricing.costs(throttles.by_target),
        prices_as_of=None if pricing is None else pricing.as_of,
    )
    report_path = Path(args.report)
    _write_reports(report, report_path)
    export_cve_judged_cases(session.audits, report_path)
    print_cve_summary(report, report_path)
    print_recording(session, _recorded_flags(args))
    if session.recording_refused:
        display.print_refusal(RECORDING_REFUSED, session.recording_refused)
        return NOT_COMPARABLE_EXIT
    return session.exit_code


def _cost_pricing(
    ungated: bool, measurement: MeasurementSettings | None, conditions: CVERunConditions
) -> CostPricing | None:
    if not ungated:
        return None  # a gated run reports no cost
    models = (conditions.model, conditions.judge_model)
    pricing = cost_pricing(load_conditions(CONDITIONS_PATH), models, measurement)
    if isinstance(pricing, str):
        console.print(f"[yellow]No cost reported: {pricing}.[/yellow]")
        return None
    return pricing


def _result(target: CVETarget, session: CVESessionResult, budget: int) -> CVEResult:
    grades = session.grades[target.cve_id]
    conditions = session.not_run.get(target.cve_id, [])
    return result_for(target, grades, budget) if grades else not_run(target, conditions)


@dataclass(frozen=True)
class _Tracking:
    throttles: SessionThrottles
    progress: AuditProgress


def _harness(args: argparse.Namespace, places: Places, tracking: _Tracking) -> CVEHarness:
    measurement = measurement_from(args)
    overrides = None if measurement is None else run_overrides(measurement)
    audit = audit_target(args.budget, tracking.throttles, places, overrides)
    return CVEHarness(
        audit=tracking.progress.tracked(bounded(audit, args.concurrency)),
        check=bounded(lambda target: check_target(target, places), args.concurrency),
        announce_audits=tracking.progress.announce,
        baselines=CVE_BASELINE_DIRECTORY,
        read_tree=read_tree,
        image_ids=image_ids,
        clock=lambda: datetime.now(UTC).isoformat(),
        places=places,
    )


def _recorded_flags(args: argparse.Namespace) -> list[str]:
    # The confirming recording refuses on a condition mismatch: it repeats the target filter and
    # every flag that enters the recorded conditions.
    cve_ids: list[str] = args.cve or []
    flags = [f"--cve {cve_id}" for cve_id in cve_ids]
    if args.runs != CVE_RUNS:
        flags.append(f"--runs {args.runs}")
    if args.budget != CVE_TEST_BUDGET:
        flags.append(f"--budget {args.budget}")
    return flags


def _write_reports(report: CVEBenchmarkReport, report_path: Path) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report.model_dump(mode="json"), indent=2))
    report_path.with_suffix(".md").write_text(render_markdown(report))


def _filter_by_cve[T: (CVETarget, OutOfScopeCVE)](items: list[T], ids: list[str] | None) -> list[T]:
    if not ids:
        return items
    wanted = set(ids)
    return [item for item in items if item.cve_id in wanted]


def _reject_unknown_cves(ids: list[str] | None, known: set[str]) -> None:
    if not ids:
        return
    unknown = set(ids) - known
    if unknown:
        console.print(f"[red]Unknown CVE id(s):[/red] {', '.join(sorted(unknown))}")
        sys.exit(2)


if __name__ == "__main__":
    main()
