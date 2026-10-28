"""Nuisance-specific commands, kept out of run_census, run_cve_benchmark and run_holdout.

`walk` prints the servers the holdout walk reached, each with its reaching flaw and the flaws
that set its version, for the maintainer to admit (no LLM, no network). `nuisance-dossier` writes
the isolated admission dossier for one server (no LLM; the fix-check driver it ships needs
Docker), copying a backend's kit builder and lifecycle under `--backend <key>`. `calibrate`
rebuilds and reproduces each fix-check fixture against the admission (Docker, no LLM). `run`
audits the admitted servers on their patched images and reports the figure, so it needs Docker and
an LLM key. `gate` audits the admitted acceptance servers with a current target and compares each
to its baseline under `evals/baselines/nuisance/`, needing Docker and an LLM key.
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
from evals.audit_progress import AuditProgress
from evals.concurrency import positive_int
from evals.eval_runs import tracing_enabled
from evals.eval_session import Refused, last_commit
from evals.holdout_census import HoldoutCensus, load_census
from evals.holdout_conditions import CONDITIONS_PATH, HoldoutConditions, load_conditions
from evals.holdout_draw import draw_order
from evals.metrics import quiet_throttle_waits
from evals.nuisance_admission import ADMISSION_PATH
from evals.nuisance_calibrate_command import add_calibrate_arguments
from evals.nuisance_commands import (
    CENSUS_PATH,
    CRASHED_EXIT,
    REFUSED_EXIT,
    committed_admission,
    malformed_input_refused,
    write_report,
)
from evals.nuisance_dossier import write_dossier
from evals.nuisance_gate_command import add_gate_arguments
from evals.nuisance_markdown import render_markdown
from evals.nuisance_population import RunPopulation, run_population
from evals.nuisance_report import build_report
from evals.nuisance_results import NuisanceRunResult
from evals.nuisance_run import (
    NUISANCE_CONCURRENCY,
    NUISANCE_RUNS,
    NuisanceDeps,
    default_deps,
    nuisance_overrides,
    run_nuisance,
)
from evals.nuisance_walk import acceptance_servers, nuisance_population
from evals.provider_errors import ProviderFatal, describe_provider_error
from evals.run_files import partial_result_kept, refuse_existing_report, write_result
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
    walk = commands.add_parser("walk", help="print the servers the holdout walk reached to admit")
    walk.set_defaults(command=_walk)
    walk.add_argument("--census", type=Path, default=CENSUS_PATH)
    dossier = commands.add_parser(
        "nuisance-dossier", help="write the isolated admission dossier for one server"
    )
    dossier.set_defaults(command=_nuisance_dossier)
    dossier.add_argument("--census", type=Path, default=CENSUS_PATH)
    dossier.add_argument("--server", required=True)
    dossier.add_argument("--out", type=Path, required=True)
    dossier.add_argument(
        "--backend", default=None, help="copy the kit builder and lifecycle of this backend (doris)"
    )
    run = commands.add_parser("run", help="audit the admitted servers and report the figure")
    run.set_defaults(command=_run)
    run.add_argument("--report", type=Path, default=Path(DEFAULT_REPORT_PATH))
    run.add_argument("--runs", type=positive_int, default=None, help="default 3, lowerable to 1")
    run.add_argument("--concurrency", type=positive_int, default=NUISANCE_CONCURRENCY)
    run.add_argument("--census", type=Path, default=CENSUS_PATH)
    run.add_argument("--admission", type=Path, default=ADMISSION_PATH)
    add_calibrate_arguments(
        commands.add_parser(
            "calibrate", help="rebuild and reproduce each fix-check fixture against the admission"
        )
    )
    gate = commands.add_parser(
        "gate", help="audit the admitted acceptance servers and compare them to their baselines"
    )
    add_gate_arguments(gate)
    return parser


def _walk(args: argparse.Namespace) -> int:
    with malformed_input_refused():
        census = load_census(args.census)
        population = nuisance_population(census)
    outcomes: dict[str, str] = {}
    for step in census.draw.walk if census.draw else []:
        outcomes.setdefault(step.identifier, step.outcome)
    print(f"{len(population)} servers reached by the walk:")
    for server in population:
        outcome = outcomes.get(server.reaching_flaw, "?")
        line = (
            f"  {server.server_package}  reached by {server.reaching_flaw} ({outcome})"
            f"  sets version: {', '.join(server.version_setting)}"
        )
        if server.mark is not None:
            line += f"  [{server.mark.value}]"
        print(line)
    return 0


def _nuisance_dossier(args: argparse.Namespace) -> int:
    with malformed_input_refused():
        census = load_census(args.census)
    write_dossier(census, args.server, args.out, args.backend)
    print(f"Admission dossier for {args.server} written to {args.out}")
    return 0


def _run(args: argparse.Namespace) -> int:
    _refuse_tracing()
    refuse_existing_report(args.report, "nuisance run refused")
    conditions = load_conditions(CONDITIONS_PATH)
    with malformed_input_refused():
        census = load_census(args.census)
        admission = committed_admission(args.admission, census)
        if admission is None or not admission.servers:
            print("no server is admitted")
            return 0
        population = run_population(
            nuisance_population(census), admission, acceptance_servers(census)
        )
    settings = load_settings()
    model_ids = list(dict.fromkeys([settings.resolve_model(), settings.resolve_judge_model()]))
    conditions.require_ready(model_ids)
    run = _audit_admitted_servers(args, _ReadyRun(census, population, conditions, settings))
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

    census: HoldoutCensus
    population: RunPopulation
    conditions: HoldoutConditions
    settings: Settings


def _audit_admitted_servers(args: argparse.Namespace, ready: _ReadyRun) -> NuisanceRunResult:
    deps = default_deps(nuisance_overrides(ready.conditions), args.concurrency)
    with partial_result_kept(args.report), Progress(console=display.console) as bar:
        return asyncio.run(
            run_nuisance(
                ready.population,
                draw_order(ready.census),
                ready.conditions,
                ready.settings,
                last_commit(args.census),
                runs=args.runs if args.runs is not None else NUISANCE_RUNS,
                concurrency=args.concurrency,
                deps=_tracked(deps, AuditProgress(bar)),
            )
        )


def _tracked(deps: NuisanceDeps, progress: AuditProgress) -> NuisanceDeps:
    return dataclasses.replace(
        deps, audit=progress.tracked(deps.audit), announce_audits=progress.announce
    )


def _refuse_tracing() -> None:
    if tracing_enabled():
        raise Refused(
            "nuisance run refused",
            ["LANGSMITH_TRACING or LANGCHAIN_TRACING_V2 is set; a nuisance run keeps no trace"],
        )


if __name__ == "__main__":
    sys.exit(main())
