"""Commands of the detection holdout layer, kept out of run_census (the census and its draw
order) and run_detection (the detection acceptance layer). The calibration dossier is written with
no LLM and no network, the calibration check needs Docker and no LLM, and the `run` command audits
the holdout targets, so it needs Docker and an LLM key.
"""

import argparse
import asyncio
import dataclasses
import sys
from argparse import _SubParsersAction  # pyright: ignore[reportPrivateUsage]
from collections.abc import Sequence
from pathlib import Path

from rich.progress import Progress

from evals import eval_display as display
from evals.concurrency import positive_int
from evals.cve.audit_progress import AuditProgress
from evals.cve.census.census import Census, load_census
from evals.cve.closed_network import check_closed_network_support
from evals.cve.detection import calibration_dossier
from evals.cve.detection.calibration_check_exit import (
    default_calibration_check_deps,
    run_calibration_check,
)
from evals.cve.detection.holdout_card_readiness import unready_cards
from evals.cve.detection.holdout_markdown import render_markdown
from evals.cve.detection.holdout_report import HoldoutReport, build_report
from evals.cve.detection.holdout_results import HoldoutRunResult
from evals.cve.detection.holdout_run import (
    HOLDOUT_RUNS,
    HoldoutDeps,
    default_deps,
    holdout_overrides,
    run_holdout_targets,
)
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.detection.targets import Target, image_tag
from evals.cve.holdout_conditions import CONDITIONS_PATH, HoldoutConditions, load_conditions
from evals.cve.places import DETECTION_PLACES, Places, load_places
from evals.cve.provider_errors import ProviderFatal, describe_provider_error
from evals.cve.run_files import partial_result_kept, refuse_existing_report, write_result
from evals.cve.run_images import (
    DOCKER_SWEEP,
    ContainerSweep,
    refuse_without_closed_networks,
    sweep_containers,
    target_services,
)
from evals.eval_session import Refused, last_commit
from evals.honeypot.runs import tracing_enabled
from evals.honeypots import REPO_ROOT
from evals.metrics import quiet_throttle_waits
from mcp_auditor.adapters.log_redaction import silenced_stdio_logging
from mcp_auditor.config import Settings, load_settings

CENSUS_PATH = REPO_ROOT / "evals" / "census.json"
DEFAULT_REPORT_PATH = "output/detection_holdout_report.json"
REFUSED_EXIT = 3
CRASHED_EXIT = 4


def main(argv: Sequence[str] | None = None) -> int:
    quiet_throttle_waits()
    args = _parser().parse_args(argv)
    try:
        with silenced_stdio_logging():
            return args.command(args)
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
    run.add_argument("--runs", type=positive_int, default=None, help="default 3, lowerable to 1")
    run.add_argument("--concurrency", type=positive_int, default=6)
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


def _census(path: Path) -> Census:
    """Only the census load reads a ValueError as a refusal: a malformed census must not read as
    success, and a ValueError raised later is a crash."""
    try:
        return load_census(path)
    except ValueError as error:
        raise Refused("Refused: the census is malformed.", [str(error)]) from error


def _calibration_dossier(args: argparse.Namespace) -> int:
    census = _census(args.census)
    calibration_dossier.write_kit(census, args.flaw, args.out)
    print(f"Calibration kit for {args.flaw} written to {args.out}")
    return 0


def _run(args: argparse.Namespace) -> int:
    _refuse_tracing()
    refuse_existing_report(args.report, "holdout run refused")
    conditions = load_conditions(CONDITIONS_PATH)
    if not HOLDOUT_TARGETS:
        print("no holdout target is drawn")
        return 0
    census = _census(args.census)
    _refuse_unready_cards(census)
    settings = load_settings()
    model_ids = list(dict.fromkeys([settings.resolve_model(), settings.resolve_judge_model()]))
    conditions.require_ready(model_ids)
    run = _audit_drawn_targets(args, _ReadyHoldoutRun(census, conditions, settings))
    write_result(args.report, run)
    report = build_report(run)
    markdown = render_markdown(report)
    _write_report(args.report, report, markdown)
    print(markdown)
    display.print_report_paths(args.report)
    return 0


def _refuse_unready_cards(census: Census) -> None:
    drawn = [target.flaw_id for target in HOLDOUT_TARGETS]
    gaps = unready_cards(census.draw, drawn)
    if gaps:
        raise Refused(
            "holdout run refused",
            ["drawn targets whose card is not ready under detection suite rule v11", *gaps],
        )


@dataclasses.dataclass(frozen=True)
class _ReadyHoldoutRun:
    """What a holdout run reads, once its cards and its conditions are checked ready."""

    census: Census
    conditions: HoldoutConditions
    settings: Settings


def _audit_drawn_targets(args: argparse.Namespace, ready: _ReadyHoldoutRun) -> HoldoutRunResult:
    disclosure_dates = {flaw.identifier: flaw.disclosure_date for flaw in ready.census.flaws}
    places = load_places(DETECTION_PLACES)
    deps = default_deps(places, holdout_overrides(ready.conditions), args.concurrency)
    with partial_result_kept(args.report), Progress(console=display.console) as bar:
        return asyncio.run(
            run_holdout_targets(
                HOLDOUT_TARGETS,
                disclosure_dates,
                ready.conditions,
                ready.settings,
                places,
                last_commit(args.census),
                runs=args.runs if args.runs is not None else HOLDOUT_RUNS,
                concurrency=args.concurrency,
                deps=_tracked(deps, AuditProgress(bar)),
            )
        )


def _tracked(deps: HoldoutDeps, progress: AuditProgress) -> HoldoutDeps:
    return dataclasses.replace(
        deps, audit=progress.tracked(deps.audit), announce_audits=progress.announce
    )


def _calibration_check(args: argparse.Namespace) -> int:
    places = load_places(DETECTION_PLACES)
    targets = [
        target for target in HOLDOUT_TARGETS if args.flaw is None or target.flaw_id == args.flaw
    ]
    if not targets:
        print("no holdout target is drawn")
        return 0
    refuse_without_closed_networks(check_closed_network_support)
    try:
        return asyncio.run(_check_calibrations(targets, places, args.concurrency, DOCKER_SWEEP))
    except ValueError as error:
        # A fixture-config error out of check_target (an unknown kept id, a planting_spec refusal)
        # is a crash, not a target out of calibration (exit 1) nor the malformed census main
        # reports (exit 3).
        display.print_refusal(
            "Refused: a detection fixture of a holdout target is misconfigured.", [str(error)]
        )
        return CRASHED_EXIT


async def _check_calibrations(
    targets: list[Target], places: Places, concurrency: int, sweep: ContainerSweep
) -> int:
    tags = [image_tag(service) for service in target_services(targets)]
    try:
        deps = default_calibration_check_deps(concurrency, ci=False)
        return await run_calibration_check(targets, places, deps)
    finally:
        sweep_containers(tags, sweep.running_containers, sweep.remove_containers)


def _refuse_tracing() -> None:
    if tracing_enabled():
        raise Refused(
            "holdout run refused",
            ["LANGSMITH_TRACING or LANGCHAIN_TRACING_V2 is set; a holdout run keeps no trace"],
        )


def _write_report(path: Path, report: HoldoutReport, markdown: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2))
    path.with_suffix(".md").write_text(markdown)


if __name__ == "__main__":
    sys.exit(main())
