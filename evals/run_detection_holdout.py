"""Commands of the detection holdout layer, kept out of run_census (the census and its draw
order) and run_detection (the detection acceptance layer). The calibration dossier is written with
no LLM and no network, the calibration check needs Docker and no LLM, and the `run` command audits
the holdout targets, so it needs Docker and an LLM key.
"""

import argparse
import asyncio
import dataclasses
import sys
from argparse import _SubParsersAction
from collections.abc import Sequence
from pathlib import Path

from rich.progress import Progress

from evals import eval_display as display
from evals.cli_arguments import positive_int
from evals.cve.audit_progress import AuditProgress
from evals.cve.census.census import CENSUS_PATH, Census, load_census
from evals.cve.detection import calibration_dossier
from evals.cve.detection.calibration_check_exit import (
    CalibrationCheckDeps,
    run_calibration_check,
)
from evals.cve.detection.holdout_card_readiness import CARD_CHECK_RULE_VERSION, unready_cards
from evals.cve.detection.holdout_command_deps import HoldoutCommandDeps
from evals.cve.detection.holdout_markdown import render_markdown
from evals.cve.detection.holdout_report import build_report
from evals.cve.detection.holdout_results import DetectionHoldoutRunResult
from evals.cve.detection.holdout_run import (
    DETECTION_HOLDOUT_RUN_REFUSED,
    HOLDOUT_CONCURRENCY,
    HOLDOUT_RUNS,
    HoldoutDeps,
    HoldoutRunInputs,
    refuse_tracing,
)
from evals.cve.detection.targets import Target
from evals.cve.holdout_conditions import HoldoutConditions
from evals.cve.images import COMPOSE_FILE, ImageStore, image_tag, stale_services
from evals.cve.launch_audit import RunOverrides
from evals.cve.places import DETECTION_PLACES, load_places
from evals.cve.provider_errors import ProviderFatal, describe_provider_error
from evals.cve.run_files import partial_result_kept, refuse_existing_report, write_result
from evals.cve.run_images import (
    ContainerSweep,
    refuse_without_closed_networks,
    sweep_containers,
    target_services,
)
from evals.eval_session import Refused
from evals.repository import REPO_ROOT
from evals.session_usage import quiet_throttle_waits
from mcp_auditor.adapters.log_redaction import silenced_stdio_logging
from mcp_auditor.config import Settings, load_settings

DEFAULT_REPORT_PATH = "output/detection_holdout_report.json"
REFUSED_EXIT = 3
CRASHED_EXIT = 4


def main(argv: Sequence[str] | None = None, deps: HoldoutCommandDeps | None = None) -> int:
    quiet_throttle_waits()
    args = _parser().parse_args(argv)
    try:
        with silenced_stdio_logging():
            return args.command(args, deps or HoldoutCommandDeps())
    except Refused as refusal:
        display.print_refusal(refusal.title, refusal.reasons)
        return REFUSED_EXIT
    except ProviderFatal as fatal:
        display.print_refusal(
            "Crashed: a fatal model provider error stopped the run.",
            [describe_provider_error(fatal.cause)],
        )
        return CRASHED_EXIT


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Commands of the detection holdout layer.")
    commands = parser.add_subparsers(required=True)
    dossier = commands.add_parser(
        "calibration-dossier", help="write the isolated calibration kit for one candidate"
    )
    dossier.set_defaults(command=_calibration_dossier)
    dossier.add_argument("--census", type=Path, default=CENSUS_PATH)
    dossier.add_argument(
        "--flaw", required=True, help="a CVE ID, or the GHSA ID of a flaw without one"
    )
    dossier.add_argument("--out", type=Path, required=True)
    run = commands.add_parser(
        "run", help="audit the holdout targets and report the holdout detection rate"
    )
    run.set_defaults(command=_run)
    run.add_argument("--report", type=Path, default=Path(DEFAULT_REPORT_PATH))
    run.add_argument(
        "--runs",
        type=positive_int,
        default=HOLDOUT_RUNS,
        help=f"default {HOLDOUT_RUNS}, lowerable to 1",
    )
    run.add_argument("--concurrency", type=positive_int, default=HOLDOUT_CONCURRENCY)
    run.add_argument("--census", type=Path, default=CENSUS_PATH)
    _add_calibration_check(commands)
    return parser


def _add_calibration_check(commands: "_SubParsersAction[argparse.ArgumentParser]") -> None:
    check = commands.add_parser(
        "calibration-check", help="run each holdout target's exploits and benign call, no LLM"
    )
    check.set_defaults(command=_calibration_check)
    check.add_argument(
        "--flaw",
        help=(
            "check only this flaw ID (a CVE ID, or the GHSA ID of a flaw without one), default:"
            " every holdout target"
        ),
    )
    check.add_argument("--concurrency", type=positive_int, default=6)


def _calibration_dossier(args: argparse.Namespace, _deps: HoldoutCommandDeps) -> int:
    census = _census(args.census)
    calibration_dossier.write_kit(census, args.flaw, args.out)
    print(f"Calibration kit for {args.flaw} written to {args.out}")
    return 0


def _census(path: Path) -> Census:
    """Only the census load reads a ValueError as a refusal: a malformed census must not read as
    success, and a ValueError raised later is a crash."""
    try:
        return load_census(path)
    except ValueError as error:
        raise Refused("Refused: the census is malformed.", [str(error)]) from error


def _run(args: argparse.Namespace, deps: HoldoutCommandDeps) -> int:
    refuse_tracing()
    refuse_existing_report(args.report, DETECTION_HOLDOUT_RUN_REFUSED)
    conditions = deps.conditions()
    if not deps.drawn:
        print("no holdout target is drawn")
        return 0
    census = _census(args.census)
    _refuse_unready_cards(census, deps.drawn)
    settings = load_settings()
    model_ids = list(dict.fromkeys([settings.resolve_model(), settings.resolve_judge_model()]))
    conditions.require_ready(model_ids)
    run = _audit_drawn_targets(args, _ReadyHoldoutRun(census, conditions, settings), deps)
    write_result(args.report, run)
    report = build_report(run)
    markdown = render_markdown(report)
    deps.write_report(args.report, report, markdown)
    print(markdown)
    display.print_report_paths(args.report)
    return 0


def _refuse_unready_cards(census: Census, drawn: Sequence[Target]) -> None:
    gaps = unready_cards(census.draw, [target.flaw_id for target in drawn])
    if gaps:
        headline = (
            "drawn targets whose card is not ready under detection suite rule"
            f" v{CARD_CHECK_RULE_VERSION}"
        )
        raise Refused(DETECTION_HOLDOUT_RUN_REFUSED, [headline, *gaps])


@dataclasses.dataclass(frozen=True)
class _ReadyHoldoutRun:
    """What a detection holdout run reads, once its cards and its conditions are checked ready."""

    census: Census
    conditions: HoldoutConditions
    settings: Settings


def _audit_drawn_targets(
    args: argparse.Namespace, ready: _ReadyHoldoutRun, deps: HoldoutCommandDeps
) -> DetectionHoldoutRunResult:
    disclosure_dates = {flaw.identifier: flaw.disclosure_date for flaw in ready.census.flaws}
    places = load_places(DETECTION_PLACES)
    holdout_deps = deps.holdout_deps(
        places, RunOverrides.of_holdout(ready.conditions), args.concurrency
    )
    inputs = HoldoutRunInputs(
        targets=deps.drawn,
        disclosure_dates=disclosure_dates,
        census_commit=deps.last_commit(args.census),
        conditions=ready.conditions,
        settings=ready.settings,
        places=places,
        runs=args.runs,
        concurrency=args.concurrency,
    )
    with partial_result_kept(args.report), Progress(console=display.console) as bar:
        return asyncio.run(
            deps.run_targets(inputs, deps=_tracked(holdout_deps, AuditProgress(bar)))
        )


def _tracked(deps: HoldoutDeps, progress: AuditProgress) -> HoldoutDeps:
    return dataclasses.replace(
        deps, audit=progress.tracked(deps.audit), announce_audits=progress.announce
    )


def _calibration_check(args: argparse.Namespace, deps: HoldoutCommandDeps) -> int:
    targets = [target for target in deps.drawn if args.flaw is None or target.flaw_id == args.flaw]
    if not targets:
        print("no holdout target is drawn")
        return 0
    refuse_without_closed_networks(deps.docker.check_networks)
    _refuse_stale_images(targets, deps.docker.images)
    checks = deps.calibration_check(args.concurrency, False)
    try:
        return asyncio.run(_check_calibrations(targets, checks, deps.docker.sweep))
    except ValueError as error:
        # A fixture-config error out of check_target (an unknown kept id, a planting_spec refusal)
        # is a crash, not a target out of calibration (exit 1) nor the malformed census main
        # reports (exit 3).
        display.print_refusal(
            "Refused: a detection fixture of a holdout target is misconfigured.", [str(error)]
        )
        return CRASHED_EXIT


def _refuse_stale_images(targets: list[Target], store: ImageStore) -> None:
    """Refused rather than rebuilt: some holdout images must be built cold by hand, and a check
    run on an image an older Dockerfile built would prove nothing about the fixture."""
    stale = stale_services(target_services(targets), store)
    if stale:
        build = f"docker compose -f {COMPOSE_FILE.relative_to(REPO_ROOT)} build {' '.join(stale)}"
        raise Refused(
            "calibration check refused",
            [*(f"the image of {service} is stale or absent" for service in stale), build],
        )


async def _check_calibrations(
    targets: list[Target], checks: CalibrationCheckDeps, sweep: ContainerSweep
) -> int:
    tags = [image_tag(service) for service in target_services(targets)]
    try:
        return await run_calibration_check(targets, load_places(DETECTION_PLACES), checks)
    finally:
        sweep_containers(tags, sweep.running_containers, sweep.remove_containers)


if __name__ == "__main__":
    sys.exit(main())
