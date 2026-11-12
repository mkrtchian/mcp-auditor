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
from evals.concurrency import bounded, positive_int
from evals.cve.audit_progress import AuditProgress
from evals.cve.detection import no_llm_modes
from evals.cve.detection.audit import audit_target
from evals.cve.detection.baseline import (
    DETECTION_BASELINE_DIRECTORY,
    DetectionRunConditions,
    image_ids,
    run_conditions,
)
from evals.cve.detection.calibration_check import check_target
from evals.cve.detection.console import print_detection_summary
from evals.cve.detection.costs import CostPricing
from evals.cve.detection.layout_check import check_layouts_and_routes
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
from evals.cve.detection.session import DetectionSessionResult, run_gated
from evals.cve.detection.session_model import DetectionHarness, DetectionOptions
from evals.cve.detection.targets import (
    ACCEPTANCE_TARGETS,
    OUT_OF_SCOPE_FLAWS,
    OutOfScopeFlaw,
    Target,
    image_tag,
)
from evals.cve.holdout_conditions import CONDITIONS_PATH, load_conditions
from evals.cve.places import DETECTION_PLACES, Places, load_places
from evals.cve.run_images import DOCKER_SWEEP, ContainerSweep, sweep_containers, target_services
from evals.detection_preflight import preflight_ok
from evals.eval_display import console
from evals.eval_session import RECORDING_REFUSED, Refused, read_tree
from evals.export import export_detection_judged_cases
from evals.metrics import SessionThrottles, quiet_throttle_waits
from mcp_auditor.adapters.log_redaction import silenced_stdio_logging
from mcp_auditor.config import load_settings

DETECTION_RUNS = 3
DETECTION_TEST_BUDGET = 10
DETECTION_CONCURRENCY = 6
DEFAULT_REPORT_PATH = "output/detection_report.json"
NOT_COMPARABLE_EXIT = 3
CRASHED_EXIT = 4


def main() -> None:
    quiet_throttle_waits()
    args = _parse_args()
    graded = _filter_by_flaw(ACCEPTANCE_TARGETS, args.flaw)
    tracked = _filter_by_flaw(OUT_OF_SCOPE_FLAWS, args.flaw)
    _reject_unknown_flaws(args.flaw, {t.flaw_id for t in (*graded, *tracked)})
    refusal = _flag_refusal(args)
    if refusal:
        display.print_refusal(RECORDING_REFUSED if args.record_baseline else "Refused.", [refusal])
        sys.exit(NOT_COMPARABLE_EXIT)

    # Says nothing of detection nor of the fixtures, so a crash in every mode.
    if not preflight_ok():
        sys.exit(CRASHED_EXIT)

    try:
        with silenced_stdio_logging():
            code = asyncio.run(_run(args, graded, tracked, DOCKER_SWEEP))
    except Refused as refused:
        display.print_refusal(refused.title, refused.reasons)
        code = NOT_COMPARABLE_EXIT
    except Exception:
        traceback.print_exc()
        code = CRASHED_EXIT
    sys.exit(code)


async def _run(
    args: argparse.Namespace,
    graded: list[Target],
    tracked: list[OutOfScopeFlaw],
    sweep: ContainerSweep,
) -> int:
    # The calibration check and the survey run under the same crash handler as the graded path, so
    # a configuration error out of either exits 4, not Python's exit 1, which reads as a target out
    # of calibration.
    places = load_places(DETECTION_PLACES)
    tags = [image_tag(service) for service in target_services(graded)]
    try:
        if args.survey:
            return await no_llm_modes.survey(args, graded, places)
        if args.calibration_check:
            return await no_llm_modes.calibration_check(args, graded, places)
        # A kept layout place without a route is a misconfigured fixture: refuse before recording.
        if args.record_baseline and await check_layouts_and_routes(graded, places, ci=args.ci):
            return 1
        return await _run_graded(args, graded, tracked, places)
    finally:
        sweep_containers(tags, sweep.running_containers, sweep.remove_containers)


def _parse_args() -> argparse.Namespace:
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
    return parser.parse_args()


def _flag_refusal(args: argparse.Namespace) -> str | None:
    if args.survey and (args.calibration_check or args.record_baseline or args.no_baseline):
        return "--survey runs no audit: it neither records nor gates"
    if args.calibration_check and (args.record_baseline or args.no_baseline):
        return "--calibration-check runs no audit: it neither records nor gates"
    if args.record_baseline and args.no_baseline:
        return (
            "--record-baseline cannot run --no-baseline: a baseline records the conditions it gates"
        )
    return measurement_refusal(args)


async def _run_graded(
    args: argparse.Namespace,
    graded: list[Target],
    tracked: list[OutOfScopeFlaw],
    places: Places,
) -> int:
    tree = read_tree()
    conditions = run_conditions(load_settings(), args.runs, args.budget)
    measurement = measurement_from(args)
    pricing = _cost_pricing(args.no_baseline, measurement, conditions)
    options = DetectionOptions(graded, conditions, args.no_baseline, args.record_baseline)
    throttles = SessionThrottles()
    with Progress(console=console) as bar:
        tracking = _Tracking(throttles, AuditProgress(bar))
        session = await run_gated(options, _harness(args, places, tracking))
    results = [_result(target, session, args.budget) for target in graded]
    results.extend(out_of_scope_results(tracked))
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
    _write_reports(report, report_path)
    export_detection_judged_cases(session.audits, report_path)
    print_detection_summary(report, report_path)
    print_recording(session, _recorded_flags(args))
    if session.recording_refused:
        display.print_refusal(RECORDING_REFUSED, session.recording_refused)
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


def _result(target: Target, session: DetectionSessionResult, budget: int) -> TargetResult:
    grades = session.grades[target.flaw_id]
    reasons = session.not_run.get(target.flaw_id, [])
    return result_for(target, grades, budget) if grades else not_run(target, reasons)


@dataclass(frozen=True)
class _Tracking:
    throttles: SessionThrottles
    progress: AuditProgress


def _harness(args: argparse.Namespace, places: Places, tracking: _Tracking) -> DetectionHarness:
    measurement = measurement_from(args)
    overrides = None if measurement is None else run_overrides(measurement)
    audit = audit_target(args.budget, tracking.throttles, places, overrides)
    return DetectionHarness(
        audit=tracking.progress.tracked(bounded(audit, args.concurrency)),
        check=bounded(lambda target: check_target(target, places), args.concurrency),
        announce_audits=tracking.progress.announce,
        baselines=DETECTION_BASELINE_DIRECTORY,
        read_tree=read_tree,
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


def _write_reports(report: DetectionReport, report_path: Path) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report.model_dump(mode="json"), indent=2))
    report_path.with_suffix(".md").write_text(render_markdown(report))


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
    main()
