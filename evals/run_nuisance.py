"""Nuisance-specific commands, kept out of run_census, run_detection and run_detection_holdout.

`walk` prints the servers the nuisance walk reached, the detection walk's then the addition's, each
with the draw position of its reaching flaw and the flaws that may count, for the maintainer to
admit, and how many of the addition's servers the admission counts in the nuisance holdout layer (no
LLM, no network). `nuisance-dossier` writes the isolated admission dossier for one server (no LLM;
the fix-check driver it ships needs Docker), copying a backend's kit builder and lifecycle under
`--backend <key>`, or under `--re-admission` the re-admission dossier of an admitted server, with
its record, its run, fix-check and backend sources and the benign probe. `fix-check` rebuilds each
fix-check fixture's images and reproduces its flaw against the admission (Docker, no LLM). `run`
audits the admitted servers on their patched images and reports the holdout nuisance rate, so it
needs Docker and an LLM key. `gate` audits each admitted nuisance acceptance server and compares it
to its baseline under `evals/baselines/nuisance/`, needing Docker and an LLM key. `vet` rebuilds the
run's images and makes each audited server's benign calls on the run's launch path (Docker, no LLM).
"""

import argparse
import asyncio
import dataclasses
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from rich.progress import Progress

from evals import eval_display as display
from evals.concurrency import positive_int
from evals.cve.audit_progress import AuditProgress
from evals.cve.census.draw_order import draw_order
from evals.cve.detection.baseline import fixture_fingerprint
from evals.cve.detection.draw_record import DrawRecord, governing_steps
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.holdout_conditions import CONDITIONS_PATH, HoldoutConditions, load_conditions
from evals.cve.nuisance.admission_walk import addition_entries
from evals.cve.nuisance.commands import (
    CENSUS_PATH,
    CRASHED_EXIT,
    REFUSED_EXIT,
    WALK_RECORD_PATH,
    committed_admission,
    committed_walk_inputs,
    malformed_input_refused,
    write_report,
)
from evals.cve.nuisance.dossier import write_dossier
from evals.cve.nuisance.fix_check_command import add_fix_check_arguments
from evals.cve.nuisance.gate_command import add_gate_arguments
from evals.cve.nuisance.holdout_calibration_copies import (
    copy_targets,
    stale_holdout_calibration_copies,
)
from evals.cve.nuisance.holdout_servers import RunPopulation, run_population
from evals.cve.nuisance.markdown import render_markdown
from evals.cve.nuisance.re_admission_dossier import write_re_admission_dossier
from evals.cve.nuisance.report import build_report
from evals.cve.nuisance.results import NuisanceRunResult
from evals.cve.nuisance.run import (
    NUISANCE_CONCURRENCY,
    NUISANCE_RUNS,
    NuisanceDeps,
    RunProvenance,
    default_deps,
    nuisance_overrides,
    run_nuisance,
)
from evals.cve.nuisance.unrecorded import refuse_unrecorded
from evals.cve.nuisance.vet_command import add_vet_arguments
from evals.cve.nuisance.walk import NuisanceServer, acceptance_target_servers, nuisance_population
from evals.cve.nuisance.walk_record import WalkInputs
from evals.cve.provider_errors import ProviderFatal, describe_provider_error
from evals.cve.run_files import partial_result_kept, refuse_existing_report, write_result
from evals.cve_places import HOLDOUT_PLACES, load_places
from evals.eval_session import Refused, last_commit
from evals.honeypot.runs import tracing_enabled
from evals.metrics import quiet_throttle_waits
from evals.nuisance_admission import ADMISSION_PATH, AdmittedServer
from mcp_auditor.adapters.log_redaction import silenced_stdio_logging
from mcp_auditor.config import Settings, load_settings

DEFAULT_REPORT_PATH = "output/nuisance_report.json"


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
    parser = argparse.ArgumentParser(description="Nuisance admission commands.")
    commands = parser.add_subparsers(required=True)
    walk = commands.add_parser("walk", help="print the servers the nuisance walk reached to admit")
    walk.set_defaults(command=_walk)
    walk.add_argument("--census", type=Path, default=CENSUS_PATH)
    walk.add_argument("--walk-record", type=Path, default=WALK_RECORD_PATH)
    walk.add_argument("--admission", type=Path, default=ADMISSION_PATH)
    dossier = commands.add_parser(
        "nuisance-dossier", help="write the isolated admission dossier for one server"
    )
    dossier.set_defaults(command=_nuisance_dossier)
    dossier.add_argument("--census", type=Path, default=CENSUS_PATH)
    dossier.add_argument("--walk-record", type=Path, default=WALK_RECORD_PATH)
    dossier.add_argument("--server", required=True)
    dossier.add_argument("--out", type=Path, required=True)
    dossier.add_argument(
        "--backend", default=None, help="copy the kit builder and lifecycle of this backend (doris)"
    )
    dossier.add_argument(
        "--re-admission", action="store_true", help="write the re-admission dossier instead"
    )
    dossier.add_argument("--admission", type=Path, default=ADMISSION_PATH)
    run = commands.add_parser(
        "run", help="audit the admitted servers and report the holdout nuisance rate"
    )
    run.set_defaults(command=_run)
    run.add_argument("--report", type=Path, default=Path(DEFAULT_REPORT_PATH))
    run.add_argument("--runs", type=positive_int, default=None, help="default 3, lowerable to 1")
    run.add_argument("--concurrency", type=positive_int, default=NUISANCE_CONCURRENCY)
    run.add_argument("--census", type=Path, default=CENSUS_PATH)
    run.add_argument("--walk-record", type=Path, default=WALK_RECORD_PATH)
    run.add_argument("--admission", type=Path, default=ADMISSION_PATH)
    add_fix_check_arguments(
        commands.add_parser(
            "fix-check", help="rebuild and reproduce each fix-check fixture against the admission"
        )
    )
    gate = commands.add_parser(
        "gate",
        help="audit the admitted nuisance acceptance servers and compare them to their baselines",
    )
    add_gate_arguments(gate)
    add_vet_arguments(
        commands.add_parser(
            "vet", help="rebuild the run's images and make each audited server's benign calls"
        )
    )
    return parser


def _walk(args: argparse.Namespace) -> int:
    with malformed_input_refused():
        walk_inputs = committed_walk_inputs(args.census, args.walk_record)
        population = nuisance_population(walk_inputs)
        admission = committed_admission(args.admission, walk_inputs)
    draw = walk_inputs.census.draw
    governing = governing_steps(draw) if draw else {}
    outcomes = {identifier: step.outcome for identifier, step in governing.items()}
    print(f"{len(population)} servers reached by the walk:")
    for server in population:
        print(_walk_line(server, outcomes))
    if admission is not None:
        admitted = len(addition_entries(admission, population))
        size = walk_inputs.record.addition.size
        print(
            f"{admitted} of {size} servers of the addition admitted"
            " and in the nuisance holdout layer"
        )
    return 0


def _walk_line(server: NuisanceServer, outcomes: dict[str, str]) -> str:
    how = "addition" if server.in_addition else outcomes[server.reaching_flaw]
    line = (
        f"  #{server.reaching_position} {server.server_package}"
        f"  reached by {server.reaching_flaw} ({how})"
        f"  may count, pending the admission's class: {', '.join(server.candidate_counted_flaws)}"
    )
    if server.mark is not None:
        line += f"  [{server.mark.value}]"
    return line


def _nuisance_dossier(args: argparse.Namespace) -> int:
    if args.re_admission:
        return _re_admission_dossier(args)
    with malformed_input_refused():
        walk_inputs = committed_walk_inputs(args.census, args.walk_record)
    write_dossier(walk_inputs, args.server, args.out, args.backend)
    print(f"Admission dossier for {args.server} written to {args.out}")
    return 0


def _re_admission_dossier(args: argparse.Namespace) -> int:
    if args.backend is not None:
        raise Refused(
            "nuisance dossier refused",
            [
                "--backend is for a first admission:"
                " a re-admission takes the backend its record names"
            ],
        )
    with malformed_input_refused():
        walk_inputs = committed_walk_inputs(args.census, args.walk_record)
        admission = committed_admission(args.admission, walk_inputs)
    if admission is None:
        raise Refused("nuisance dossier refused", [f"no admission at {args.admission}"])
    write_re_admission_dossier(walk_inputs, admission, args.server, args.out)
    print(f"Re-admission dossier for {args.server} written to {args.out}")
    return 0


def _run(args: argparse.Namespace) -> int:
    _refuse_tracing()
    refuse_existing_report(args.report, "nuisance run refused")
    conditions = load_conditions(CONDITIONS_PATH)
    with malformed_input_refused():
        walk_inputs = committed_walk_inputs(args.census, args.walk_record)
        admission = committed_admission(args.admission, walk_inputs)
        if admission is None or not admission.servers:
            print("no server is admitted")
            return 0
        population = run_population(
            nuisance_population(walk_inputs), admission, acceptance_target_servers(walk_inputs)
        )
    refuse_unrecorded(population.audited, "nuisance run refused")
    _refuse_stale_holdout_calibration_copies(population.audited, walk_inputs.census.draw)
    settings = load_settings()
    model_ids = list(dict.fromkeys([settings.resolve_model(), settings.resolve_judge_model()]))
    conditions.require_ready(model_ids)
    run = _audit_admitted_servers(args, _ReadyRun(walk_inputs, population, conditions, settings))
    write_result(args.report, run)
    report = build_report(run)
    markdown = render_markdown(report)
    write_report(args.report, report, markdown)
    print(markdown)
    display.print_report_paths(args.report)
    return 0


@dataclass(frozen=True)
class _ReadyRun:
    """What a nuisance run reads, once its conditions are checked ready for its models."""

    walk_inputs: WalkInputs
    population: RunPopulation
    conditions: HoldoutConditions
    settings: Settings


def _audit_admitted_servers(args: argparse.Namespace, ready: _ReadyRun) -> NuisanceRunResult:
    deps = default_deps(nuisance_overrides(ready.conditions), args.concurrency)
    with partial_result_kept(args.report), Progress(console=display.console) as bar:
        return asyncio.run(
            run_nuisance(
                ready.population,
                draw_order(ready.walk_inputs.census),
                ready.conditions,
                ready.settings,
                RunProvenance(last_commit(args.census), last_commit(args.walk_record)),
                runs=args.runs if args.runs is not None else NUISANCE_RUNS,
                concurrency=args.concurrency,
                deps=_tracked(deps, AuditProgress(bar)),
            )
        )


def _tracked(deps: NuisanceDeps, progress: AuditProgress) -> NuisanceDeps:
    return dataclasses.replace(
        deps, audit=progress.tracked(deps.audit), announce_audits=progress.announce
    )


def _refuse_stale_holdout_calibration_copies(
    servers: Sequence[AdmittedServer], draw: DrawRecord | None
) -> None:
    places = load_places(HOLDOUT_PLACES)
    fingerprints = {
        target.flaw_id: fixture_fingerprint(target, places) for target in HOLDOUT_TARGETS
    }
    resolution = copy_targets([target.flaw_id for target in HOLDOUT_TARGETS], draw)
    current = {copy: fingerprints[drawn] for copy, drawn in resolution.items()}
    stale = stale_holdout_calibration_copies(servers, current)
    if stale:
        reason = (
            "holdout calibration copies taken from a fixture that has since changed"
            " or left the detection holdout layer"
        )
        raise Refused("nuisance run refused", [reason, *stale])


def _refuse_tracing() -> None:
    if tracing_enabled():
        raise Refused(
            "nuisance run refused",
            ["LANGSMITH_TRACING or LANGCHAIN_TRACING_V2 is set; a nuisance run keeps no trace"],
        )


if __name__ == "__main__":
    sys.exit(main())
