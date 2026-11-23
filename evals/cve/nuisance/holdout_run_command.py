"""The `run` subcommand of run_nuisance: audit the admitted servers on their patched images and
report the holdout nuisance rate (Docker and an LLM key). Its own checks (tracing, the report paths,
the admission, unrecorded fields, stale holdout calibration copies) refuse before any Docker or LLM
work, and the run result is written before the report."""

import argparse
import asyncio
import dataclasses
import functools
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from rich.progress import Progress

from evals import eval_display as display
from evals.cli_arguments import positive_int
from evals.cve.audit_progress import AuditProgress
from evals.cve.census.census import CENSUS_PATH
from evals.cve.census.draw_order import draw_order
from evals.cve.detection.audit import RunOverrides
from evals.cve.detection.baseline import fixture_fingerprint
from evals.cve.detection.draw_record import DrawRecord
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.holdout_conditions import HoldoutConditions, committed_conditions
from evals.cve.nuisance.admission.admission import ADMISSION_PATH, AdmittedServer
from evals.cve.nuisance.admission.holdout_calibration_copies import (
    copy_targets,
    stale_holdout_calibration_copies,
)
from evals.cve.nuisance.admission.unrecorded import refuse_unrecorded
from evals.cve.nuisance.admission.walk import acceptance_target_servers, reached_servers
from evals.cve.nuisance.admission.walk_record import WalkInputs
from evals.cve.nuisance.commands import (
    WALK_RECORD_PATH,
    committed_admission,
    committed_walk_inputs,
    malformed_input_refused,
)
from evals.cve.nuisance.holdout_run import (
    NUISANCE_CONCURRENCY,
    NUISANCE_RUNS,
    NuisanceDeps,
    RunOrchestrator,
    RunProvenance,
    default_deps,
    nuisance_overrides,
    run_nuisance,
)
from evals.cve.nuisance.holdout_servers import RunPopulation, run_population
from evals.cve.nuisance.markdown import render_markdown
from evals.cve.nuisance.report import build_report
from evals.cve.nuisance.results import NuisanceHoldoutRunResult
from evals.cve.places import DETECTION_PLACES, load_places
from evals.cve.run_files import (
    ReportWriter,
    partial_result_kept,
    refuse_existing_report,
    write_report,
    write_result,
)
from evals.eval_session import Refused, last_commit
from evals.honeypot.runs import tracing_enabled
from mcp_auditor.config import Settings, load_settings

DEFAULT_REPORT_PATH = "output/nuisance_report.json"


@dataclass(frozen=True)
class RunCommandDeps:
    conditions: Callable[[], HoldoutConditions] = committed_conditions
    settings: Callable[[], Settings] = load_settings
    run_deps: Callable[[RunOverrides, int], NuisanceDeps] = default_deps
    orchestrate: RunOrchestrator = run_nuisance
    file_commit: Callable[[Path], str] = last_commit
    write_report: ReportWriter = write_report


def add_run_arguments(parser: argparse.ArgumentParser, deps: RunCommandDeps) -> None:
    parser.set_defaults(command=functools.partial(run, deps=deps))
    parser.add_argument("--report", type=Path, default=Path(DEFAULT_REPORT_PATH))
    parser.add_argument(
        "--runs", type=positive_int, default=None, help=f"default {NUISANCE_RUNS}, lowerable to 1"
    )
    parser.add_argument("--concurrency", type=positive_int, default=NUISANCE_CONCURRENCY)
    parser.add_argument("--census", type=Path, default=CENSUS_PATH)
    parser.add_argument("--walk-record", type=Path, default=WALK_RECORD_PATH)
    parser.add_argument("--admission", type=Path, default=ADMISSION_PATH)


def run(args: argparse.Namespace, deps: RunCommandDeps) -> int:
    _refuse_tracing()
    refuse_existing_report(args.report, "nuisance holdout run refused")
    conditions = deps.conditions()
    with malformed_input_refused():
        walk_inputs = committed_walk_inputs(args.census, args.walk_record)
        admission = committed_admission(args.admission, walk_inputs)
        if admission is None or not admission.servers:
            print("no server is admitted")
            return 0
        population = run_population(
            reached_servers(walk_inputs), admission, acceptance_target_servers(walk_inputs)
        )
    refuse_unrecorded(population.audited, "nuisance holdout run refused")
    _refuse_stale_holdout_calibration_copies(population.audited, walk_inputs.census.draw)
    settings = deps.settings()
    model_ids = list(dict.fromkeys([settings.resolve_model(), settings.resolve_judge_model()]))
    conditions.require_ready(model_ids)
    ready = _ReadyRun(walk_inputs, population, conditions, settings)
    result = _audit_admitted_servers(args, ready, deps)
    write_result(args.report, result)
    report = build_report(result)
    markdown = render_markdown(report)
    deps.write_report(args.report, report, markdown)
    print(markdown)
    display.print_report_paths(args.report)
    return 0


def _refuse_tracing() -> None:
    if tracing_enabled():
        raise Refused(
            "nuisance holdout run refused",
            [
                "LANGSMITH_TRACING or LANGCHAIN_TRACING_V2 is set; "
                "a nuisance holdout run keeps no trace"
            ],
        )


def _refuse_stale_holdout_calibration_copies(
    servers: Sequence[AdmittedServer], draw: DrawRecord | None
) -> None:
    stale = stale_holdout_calibration_copies(servers, current_copy_fingerprints(draw))
    if stale:
        reason = (
            "holdout calibration copies taken from a fixture that has since changed"
            " or left the detection holdout layer"
        )
        raise Refused("nuisance holdout run refused", [reason, *stale])


def current_copy_fingerprints(draw: DrawRecord | None) -> dict[str, str]:
    """The fixture fingerprint of the drawn target each copyable flaw's copy resolves to."""
    places = load_places(DETECTION_PLACES)
    fingerprints = {
        target.flaw_id: fixture_fingerprint(target, places) for target in HOLDOUT_TARGETS
    }
    resolution = copy_targets([target.flaw_id for target in HOLDOUT_TARGETS], draw)
    return {copy: fingerprints[drawn] for copy, drawn in resolution.items()}


@dataclass(frozen=True)
class _ReadyRun:
    """What a nuisance holdout run reads, once its conditions are checked ready for its models."""

    walk_inputs: WalkInputs
    population: RunPopulation
    conditions: HoldoutConditions
    settings: Settings


def _audit_admitted_servers(
    args: argparse.Namespace, ready: _ReadyRun, deps: RunCommandDeps
) -> NuisanceHoldoutRunResult:
    run_deps = deps.run_deps(nuisance_overrides(ready.conditions), args.concurrency)
    with partial_result_kept(args.report), Progress(console=display.console) as bar:
        return asyncio.run(
            deps.orchestrate(
                ready.population,
                draw_order(ready.walk_inputs.census),
                ready.conditions,
                ready.settings,
                RunProvenance(
                    deps.file_commit(args.census),
                    deps.file_commit(args.walk_record),
                    deps.file_commit(args.admission),
                ),
                runs=args.runs if args.runs is not None else NUISANCE_RUNS,
                concurrency=args.concurrency,
                deps=_tracked(run_deps, AuditProgress(bar)),
            )
        )


def _tracked(deps: NuisanceDeps, progress: AuditProgress) -> NuisanceDeps:
    return dataclasses.replace(
        deps, audit=progress.tracked(deps.audit), announce_audits=progress.announce
    )
