import argparse
import asyncio
import sys
import traceback
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from rich.progress import Progress

from evals import eval_display as display
from evals.cli_arguments import positive_int
from evals.concurrency import bounded
from evals.cve.audit_progress import AuditProgress
from evals.cve.detection.baseline import (
    DETECTION_BASELINE_DIRECTORY,
    DetectionRunConditions,
    run_conditions,
)
from evals.cve.detection.calibration_check import check_target
from evals.cve.detection.calibration_check_exit import run_calibration_check
from evals.cve.detection.command_deps import DetectionCommandDeps
from evals.cve.detection.console import print_detection_summary
from evals.cve.detection.costs import CostPricing
from evals.cve.detection.judged_cases_export import export_detection_judged_cases
from evals.cve.detection.layout_observation import observe_layout
from evals.cve.detection.markdown import render_markdown
from evals.cve.detection.measurement import (
    MeasurementSettings,
    add_measurement_flags,
    cost_pricing,
    measurement_from,
    measurement_refusal,
    run_overrides,
)
from evals.cve.detection.oracle import (
    DetectionReport,
    TargetResult,
    not_run,
    out_of_scope_results,
    result_for,
)
from evals.cve.detection.recording_console import print_recording
from evals.cve.detection.session import DetectionSessionResult
from evals.cve.detection.session_model import DetectionHarness, DetectionOptions
from evals.cve.detection.survey import survey_all
from evals.cve.detection.targets import (
    ACCEPTANCE_TARGETS,
    OUT_OF_SCOPE_FLAWS,
    OutOfScopeFlaw,
    Target,
)
from evals.cve.holdout_conditions import CONDITIONS_PATH, load_conditions
from evals.cve.images import image_ids, image_tag
from evals.cve.launch_audit import NO_OVERRIDES
from evals.cve.places import DETECTION_PLACES, Places, load_places
from evals.cve.provider_errors import ProviderFatal, describe_provider_error
from evals.cve.run_files import write_report
from evals.cve.run_images import sweep_containers, target_services
from evals.eval_display import console
from evals.eval_session import RECORD_WITHOUT_BASELINE, RECORDING_REFUSED, Refused
from evals.gate_outcome import CRASHED_EXIT, NOT_COMPARABLE_EXIT
from evals.session_usage import SessionThrottles, quiet_throttle_waits
from mcp_auditor.adapters.log_redaction import silenced_stdio_logging
from mcp_auditor.config import load_settings

DETECTION_RUNS = 3
DETECTION_TEST_BUDGET = 10
DETECTION_CONCURRENCY = 6
DEFAULT_REPORT_PATH = "output/detection_report.json"


def main(argv: Sequence[str] | None = None, deps: DetectionCommandDeps | None = None) -> int:
    deps = DetectionCommandDeps() if deps is None else deps
    quiet_throttle_waits()
    args = _parse_args(argv)
    flaws = _FlawSelection(
        graded=_filter_by_flaw(ACCEPTANCE_TARGETS, args.flaw),
        tracked=_filter_by_flaw(OUT_OF_SCOPE_FLAWS, args.flaw),
    )
    _reject_unknown_flaws(args.flaw, {t.flaw_id for t in (*flaws.graded, *flaws.tracked)})
    refusal = _flag_refusal(args)
    if refusal:
        display.print_titled_reasons(
            RECORDING_REFUSED if args.record_baseline else "Refused.", [refusal]
        )
        return NOT_COMPARABLE_EXIT

    # Says nothing of detection nor of the fixtures, so a crash in every mode.
    if not deps.preflight():
        return CRASHED_EXIT

    try:
        with silenced_stdio_logging():
            return asyncio.run(_run(args, flaws, deps))
    except Refused as refused:
        display.print_titled_reasons(refused.title, refused.reasons)
        return NOT_COMPARABLE_EXIT
    except ProviderFatal as fatal:
        display.print_titled_reasons(
            "Crashed: a fatal model provider error stopped the run.",
            [describe_provider_error(fatal.cause)],
        )
        return CRASHED_EXIT
    except Exception:
        traceback.print_exc()
        return CRASHED_EXIT


@dataclass(frozen=True)
class _FlawSelection:
    graded: list[Target]
    tracked: list[OutOfScopeFlaw]


@dataclass(frozen=True)
class _CommandRun:
    places: Places
    deps: DetectionCommandDeps


async def _run(args: argparse.Namespace, flaws: _FlawSelection, deps: DetectionCommandDeps) -> int:
    # The calibration check and the survey run under the same crash handler as the graded path, so
    # a configuration error out of either exits 4, not Python's exit 1, which reads as a target out
    # of calibration.
    places = load_places(DETECTION_PLACES)
    tags = [image_tag(service) for service in target_services(flaws.graded)]
    try:
        if args.survey:
            await survey_all(
                flaws.graded,
                bounded(lambda target: deps.survey_one(target, places), args.concurrency),
            )
            return 0
        if args.calibration_check:
            checks = deps.calibration_check(args.concurrency, args.ci)
            return await run_calibration_check(flaws.graded, places, checks)
        return await _run_graded(args, flaws, _CommandRun(places, deps))
    finally:
        sweep_containers(tags, deps.sweep.running_containers, deps.sweep.remove_containers)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the detection suite of the CVE benchmark")
    parser.add_argument("--runs", type=int, default=DETECTION_RUNS)
    parser.add_argument("--budget", type=int, default=DETECTION_TEST_BUDGET)
    parser.add_argument("--report", type=str, default=DEFAULT_REPORT_PATH)
    parser.add_argument(
        "--concurrency",
        type=positive_int,
        default=DETECTION_CONCURRENCY,
        help=(
            "Audits (or calibration checks) in flight at once, runs and retests alike; 1 runs "
            "them one after the other."
        ),
    )
    parser.add_argument(
        "--calibration-check",
        action="store_true",
        help=(
            "No-LLM calibration check per target: runs the exploits and the benign call, and "
            "confirms each target is live on the vulnerable version and fixed on the patched one."
        ),
    )
    parser.add_argument(
        "--survey",
        action="store_true",
        help="No-LLM survey: plant every in-scope candidate and report what each surfaces.",
    )
    parser.add_argument(
        "--flaw",
        action="append",
        metavar="FLAW-ID",
        help=(
            "Run only these flaws, by flaw ID: a CVE ID, or the GHSA ID of a flaw without one "
            "(repeatable). Default: all."
        ),
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Skip targets marked CI-unstable (ci_skip_reason); for the calibration check in CI.",
    )
    parser.add_argument(
        "--record-baseline",
        action="store_true",
        help=(
            "Record one file per target in evals/baselines/detection/ from a clean tree: run it "
            "twice at one commit on the local images (unconfirmed, then confirmed), commit by hand."
        ),
    )
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="Run and report without comparing to evals/baselines/detection/ (exit 0).",
    )
    add_measurement_flags(parser)
    return parser.parse_args(argv)


def _flag_refusal(args: argparse.Namespace) -> str | None:
    if args.survey and (args.calibration_check or args.record_baseline or args.no_baseline):
        return "--survey runs no audit: it neither records nor gates"
    if args.calibration_check and (args.record_baseline or args.no_baseline):
        return "--calibration-check runs no audit: it neither records nor gates"
    if args.record_baseline and args.no_baseline:
        return RECORD_WITHOUT_BASELINE
    return measurement_refusal(args)


async def _run_graded(args: argparse.Namespace, flaws: _FlawSelection, run: _CommandRun) -> int:
    tree = run.deps.read_tree()
    conditions = run_conditions(load_settings(), args.runs, args.budget)
    measurement = measurement_from(args)
    pricing = _cost_pricing(args.no_baseline, measurement, conditions)
    options = DetectionOptions(flaws.graded, conditions, args.no_baseline, args.record_baseline)
    throttles = SessionThrottles()
    with Progress(console=console) as bar:
        tracking = _Tracking(throttles, AuditProgress(bar))
        session = await run.deps.session(options, _harness(args, run, tracking))
    results = [_result(target, session, args.budget) for target in flaws.graded]
    results.extend(out_of_scope_results(flaws.tracked))
    report = DetectionReport(
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
    write_report(report_path, report, render_markdown(report))
    export_detection_judged_cases(session.audits, report_path)
    print_detection_summary(report, report_path)
    print_recording(session, _recorded_flags(args))
    if session.recording_refused:
        display.print_titled_reasons(RECORDING_REFUSED, session.recording_refused)
        return NOT_COMPARABLE_EXIT
    return session.exit_code


def _cost_pricing(
    no_baseline: bool, measurement: MeasurementSettings | None, conditions: DetectionRunConditions
) -> CostPricing | None:
    if not no_baseline:
        return None  # a gated run reports no cost
    models = (conditions.model, conditions.judge_model)
    pricing = cost_pricing(load_conditions(CONDITIONS_PATH), models, measurement)
    if isinstance(pricing, str):
        console.print(f"[yellow]No cost reported: {pricing}.[/yellow]")
        return None
    return pricing


def _result(target: Target, session: DetectionSessionResult, test_budget: int) -> TargetResult:
    grades = session.grades[target.flaw_id]
    reasons = session.not_run.get(target.flaw_id, [])
    return result_for(target, grades, test_budget) if grades else not_run(target, reasons)


@dataclass(frozen=True)
class _Tracking:
    throttles: SessionThrottles
    progress: AuditProgress


def _harness(args: argparse.Namespace, run: _CommandRun, tracking: _Tracking) -> DetectionHarness:
    measurement = measurement_from(args)
    overrides = NO_OVERRIDES if measurement is None else run_overrides(measurement)
    places = run.places
    audit = run.deps.audit_target(args.budget, tracking.throttles, places, overrides)
    return DetectionHarness(
        audit=tracking.progress.tracked(bounded(audit, args.concurrency)),
        check=bounded(lambda target: check_target(target, places), args.concurrency),
        layout=bounded(lambda target: observe_layout(target, places), args.concurrency),
        announce_audits=tracking.progress.announce,
        baselines=DETECTION_BASELINE_DIRECTORY,
        read_tree=run.deps.read_tree,
        image_ids=image_ids,
        clock=lambda: datetime.now(UTC).isoformat(),
        places=places,
    )


def _recorded_flags(args: argparse.Namespace) -> list[str]:
    # The confirming recording refuses on a condition mismatch: it repeats the target filter and
    # every flag that enters the recorded conditions.
    flaw_ids: list[str] = args.flaw or []
    flags = [f"--flaw {flaw_id}" for flaw_id in flaw_ids]
    if args.runs != DETECTION_RUNS:
        flags.append(f"--runs {args.runs}")
    if args.budget != DETECTION_TEST_BUDGET:
        flags.append(f"--budget {args.budget}")
    return flags


def _filter_by_flaw[T: (Target, OutOfScopeFlaw)](items: list[T], ids: list[str] | None) -> list[T]:
    if not ids:
        return items
    wanted = set(ids)
    return [item for item in items if item.flaw_id in wanted]


def _reject_unknown_flaws(ids: list[str] | None, known: set[str]) -> None:
    if not ids:
        return
    unknown = set(ids) - known
    if unknown:
        console.print(f"[red]Unknown flaw ID(s):[/red] {', '.join(sorted(unknown))}")
        sys.exit(2)


if __name__ == "__main__":
    sys.exit(main())
