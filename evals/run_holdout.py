"""Holdout-specific commands, kept out of run_census (the census and its draw order) and
run_cve_benchmark (the benchmark). The calibration-dossier scaffolding runs with no LLM and no
network; the `run` command audits the drawn targets, so it needs Docker and an LLM key.
"""

import argparse
import asyncio
import dataclasses
import sys
from argparse import _SubParsersAction  # pyright: ignore[reportPrivateUsage]
from collections.abc import Sequence
from pathlib import Path

from rich.progress import Progress

from evals import calibration_dossier
from evals import eval_display as display
from evals.admission_calibration import calibrate_admitted, default_calibration_deps
from evals.audit_progress import AuditProgress
from evals.closed_network import check_closed_network_support
from evals.concurrency import positive_int
from evals.cve.census.census import Census, load_census
from evals.cve_places import HOLDOUT_PLACES, Places, load_places
from evals.cve_targets import CVETarget, image_tag
from evals.eval_session import Refused, last_commit
from evals.holdout_card_readiness import unready_cards
from evals.holdout_conditions import CONDITIONS_PATH, HoldoutConditions, load_conditions
from evals.holdout_markdown import render_markdown
from evals.holdout_report import HoldoutReport, build_report
from evals.holdout_results import HoldoutRunResult
from evals.holdout_run import (
    HOLDOUT_RUNS,
    HoldoutDeps,
    default_deps,
    holdout_overrides,
    run_holdout,
)
from evals.holdout_targets import HOLDOUT_TARGETS
from evals.honeypot.runs import tracing_enabled
from evals.honeypots import REPO_ROOT
from evals.metrics import quiet_throttle_waits
from evals.provider_errors import ProviderFatal, describe_provider_error
from evals.run_files import partial_result_kept, refuse_existing_report, write_result
from evals.run_images import (
    DOCKER_SWEEP,
    ContainerSweep,
    refuse_without_closed_networks,
    sweep_containers,
    target_services,
)
from mcp_auditor.adapters.log_redaction import silenced_stdio_logging
from mcp_auditor.config import Settings, load_settings

CENSUS_PATH = REPO_ROOT / "evals" / "census.json"
DEFAULT_REPORT_PATH = "output/holdout_report.json"
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
    parser = argparse.ArgumentParser(description="Holdout draw commands.")
    commands = parser.add_subparsers(required=True)
    dossier = commands.add_parser(
        "calibration-dossier", help="write the isolated calibration kit for one candidate"
    )
    dossier.set_defaults(command=_calibration_dossier)
    dossier.add_argument("--census", type=Path, default=CENSUS_PATH)
    dossier.add_argument("--cve", required=True)
    dossier.add_argument("--out", type=Path, required=True)
    run = commands.add_parser("run", help="audit the drawn targets and report the capability")
    run.set_defaults(command=_run)
    run.add_argument("--report", type=Path, default=Path(DEFAULT_REPORT_PATH))
    run.add_argument("--runs", type=positive_int, default=None, help="default 3, lowerable to 1")
    run.add_argument("--concurrency", type=positive_int, default=6)
    run.add_argument("--census", type=Path, default=CENSUS_PATH)
    _add_calibrate(commands)
    return parser


def _add_calibrate(commands: "_SubParsersAction[argparse.ArgumentParser]") -> None:
    calibrate = commands.add_parser(
        "calibrate", help="replay each drawn target's exploits and benign call, no LLM"
    )
    calibrate.set_defaults(command=_calibrate)
    calibrate.add_argument("--cve", help="calibrate only this CVE id; default: every drawn target")
    calibrate.add_argument("--concurrency", type=positive_int, default=6)


def _census(path: Path) -> Census:
    """Only the census load reads a ValueError as a refusal: a malformed census must not read as
    success, and a ValueError raised later is a crash."""
    try:
        return load_census(path)
    except ValueError as error:
        raise Refused("Refused: the census is malformed.", [str(error)]) from error


def _calibration_dossier(args: argparse.Namespace) -> int:
    census = _census(args.census)
    calibration_dossier.write_kit(census, args.cve, args.out)
    print(f"Calibration kit for {args.cve} written to {args.out}")
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
    drawn = [target.cve_id for target in HOLDOUT_TARGETS]
    gaps = unready_cards(census.draw, drawn)
    if gaps:
        raise Refused(
            "holdout run refused",
            ["drawn targets whose card is not ready under holdout rule v11", *gaps],
        )


@dataclasses.dataclass(frozen=True)
class _ReadyHoldoutRun:
    """What a holdout run reads, once its cards and its conditions are checked ready."""

    census: Census
    conditions: HoldoutConditions
    settings: Settings


def _audit_drawn_targets(args: argparse.Namespace, ready: _ReadyHoldoutRun) -> HoldoutRunResult:
    disclosure_dates = {flaw.identifier: flaw.disclosure_date for flaw in ready.census.flaws}
    places = load_places(HOLDOUT_PLACES)
    deps = default_deps(places, holdout_overrides(ready.conditions), args.concurrency)
    with partial_result_kept(args.report), Progress(console=display.console) as bar:
        return asyncio.run(
            run_holdout(
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


def _calibrate(args: argparse.Namespace) -> int:
    places = load_places(HOLDOUT_PLACES)
    targets = [
        target for target in HOLDOUT_TARGETS if args.cve is None or target.cve_id == args.cve
    ]
    if not targets:
        print("no holdout target is drawn")
        return 0
    refuse_without_closed_networks(check_closed_network_support)
    try:
        return asyncio.run(_calibrate_targets(targets, places, args.concurrency, DOCKER_SWEEP))
    except ValueError as error:
        # A fixture-config error out of check_target (an unknown kept id, a planting_spec refusal)
        # is a crash, not a dead fixture (exit 1) nor the malformed census main reports (exit 3).
        display.print_refusal("Refused: a holdout fixture is misconfigured.", [str(error)])
        return CRASHED_EXIT


async def _calibrate_targets(
    targets: list[CVETarget], places: Places, concurrency: int, sweep: ContainerSweep
) -> int:
    tags = [image_tag(service) for service in target_services(targets)]
    try:
        deps = default_calibration_deps(concurrency, ci=False)
        return await calibrate_admitted(targets, places, deps)
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
