"""Nuisance-specific commands, kept out of run_census, run_cve_benchmark and run_holdout.

`walk` prints the servers the holdout walk reached, each with its reaching flaw and the flaws
that set its version, for the maintainer to admit (no LLM, no network). `nuisance-dossier` writes
the isolated admission dossier for one server (no LLM; the fix-check driver it ships needs
Docker). `run` audits the admitted servers on their patched images and reports the figure, so it
needs Docker and an LLM key. No server is admitted yet.
"""

import argparse
import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path

from evals import eval_display as display
from evals.concurrency import positive_int
from evals.eval_runs import tracing_enabled
from evals.eval_session import Refused, last_commit
from evals.holdout_census import load_census
from evals.holdout_conditions import CONDITIONS_PATH, load_conditions
from evals.holdout_draw import draw_order
from evals.honeypots import REPO_ROOT
from evals.metrics import quiet_throttle_waits
from evals.nuisance_admission import ADMISSION_PATH, load_admission
from evals.nuisance_dossier import write_dossier
from evals.nuisance_markdown import render_markdown
from evals.nuisance_population import run_population
from evals.nuisance_report import NuisanceReport, build_report
from evals.nuisance_run import NUISANCE_CONCURRENCY, NUISANCE_RUNS, run_nuisance
from evals.nuisance_walk import acceptance_servers, nuisance_population
from mcp_auditor.config import load_settings

CENSUS_PATH = REPO_ROOT / "evals" / "holdout_census.json"
DEFAULT_REPORT_PATH = "output/nuisance_report.json"
REFUSED_EXIT = 3


def main(argv: Sequence[str] | None = None) -> int:
    quiet_throttle_waits()
    args = _parser().parse_args(argv)
    try:
        return args.command(args)
    except Refused as refusal:
        display.print_refusal(refusal.title, refusal.reasons)
        return REFUSED_EXIT
    except ValueError as error:
        # A malformed census or admission must not read as success.
        display.print_refusal("Refused: the census or the admission is malformed.", [str(error)])
        return REFUSED_EXIT


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
    run = commands.add_parser("run", help="audit the admitted servers and report the figure")
    run.set_defaults(command=_run)
    run.add_argument("--report", type=Path, default=Path(DEFAULT_REPORT_PATH))
    run.add_argument("--runs", type=positive_int, default=None, help="default 3, lowerable to 1")
    run.add_argument("--concurrency", type=positive_int, default=NUISANCE_CONCURRENCY)
    run.add_argument("--census", type=Path, default=CENSUS_PATH)
    run.add_argument("--admission", type=Path, default=ADMISSION_PATH)
    return parser


def _walk(args: argparse.Namespace) -> int:
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
    census = load_census(args.census)
    write_dossier(census, args.server, args.out)
    print(f"Admission dossier for {args.server} written to {args.out}")
    return 0


def _run(args: argparse.Namespace) -> int:
    _refuse_tracing()
    conditions = load_conditions(CONDITIONS_PATH)
    census = load_census(args.census)
    try:
        admission = load_admission(args.admission, census)
    except FileNotFoundError:
        admission = None
    if admission is None or not admission.servers:
        print("no server is admitted")
        return 0
    settings = load_settings()
    model_ids = list(dict.fromkeys([settings.resolve_model(), settings.resolve_judge_model()]))
    conditions.require_ready(model_ids)
    run = asyncio.run(
        run_nuisance(
            run_population(nuisance_population(census), admission, acceptance_servers(census)),
            draw_order(census),
            conditions,
            settings,
            last_commit(args.census),
            runs=args.runs if args.runs is not None else NUISANCE_RUNS,
            concurrency=args.concurrency,
        )
    )
    report = build_report(run)
    markdown = render_markdown(report)
    _write_report(args.report, report, markdown)
    print(markdown)
    return 0


def _refuse_tracing() -> None:
    if tracing_enabled():
        raise Refused(
            "nuisance run refused",
            ["LANGSMITH_TRACING or LANGCHAIN_TRACING_V2 is set; a nuisance run keeps no trace"],
        )


def _write_report(path: Path, report: NuisanceReport, markdown: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2))
    path.with_suffix(".md").write_text(markdown)


if __name__ == "__main__":
    sys.exit(main())
