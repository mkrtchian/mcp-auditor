"""Nuisance-specific commands, kept out of run_census, run_cve_benchmark and run_holdout.

`walk` prints the servers the holdout walk reached, each with its reaching flaw and the flaws
that set its version, for the maintainer to admit (no LLM, no network). `nuisance-dossier` writes
the isolated admission dossier for one server (no LLM; the fix-check driver it ships needs
Docker), copying a backend's kit builder and lifecycle under `--backend <key>`. `run` audits the
admitted servers on their patched images and reports the figure, so it
needs Docker and an LLM key. `gate` audits the admitted acceptance servers with a current target
and compares each to its baseline under `evals/baselines/nuisance/`, needing Docker and an LLM
key. No server is admitted yet.
"""

import argparse
import asyncio
import sys
import traceback
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel

from evals import eval_display as display
from evals.baseline import BaselineStatus
from evals.concurrency import positive_int
from evals.eval_runs import tracing_enabled
from evals.eval_session import Refused, last_commit, read_tree
from evals.export import export_nuisance_gate_judged_cases
from evals.holdout_census import HoldoutCensus, load_census
from evals.holdout_conditions import CONDITIONS_PATH, load_conditions
from evals.holdout_draw import draw_order
from evals.honeypots import REPO_ROOT
from evals.metrics import quiet_throttle_waits
from evals.nuisance_admission import (
    ADMISSION_PATH,
    AdmittedServer,
    NuisanceAdmission,
    load_admission,
)
from evals.nuisance_dossier import write_dossier
from evals.nuisance_gate_baseline import (
    NUISANCE_GATE_BASELINE_DIRECTORY,
    NUISANCE_GATE_RUNS,
    baseline_file_name,
    gate_conditions,
)
from evals.nuisance_gate_report import NuisanceGateReport, server_lines
from evals.nuisance_gate_report import render_markdown as render_gate_markdown
from evals.nuisance_gate_session import (
    default_harness,
    gate_servers,
    not_admitted,
    outside_gate,
    run_gate,
)
from evals.nuisance_gate_session_model import NuisanceGateOptions, NuisanceGateSession
from evals.nuisance_markdown import render_markdown
from evals.nuisance_population import run_population
from evals.nuisance_report import build_report
from evals.nuisance_run import NUISANCE_CONCURRENCY, NUISANCE_RUNS, run_nuisance
from evals.nuisance_walk import (
    acceptance_servers,
    current_acceptance_servers,
    nuisance_population,
)
from mcp_auditor.config import load_settings

CENSUS_PATH = REPO_ROOT / "evals" / "holdout_census.json"
DEFAULT_REPORT_PATH = "output/nuisance_report.json"
DEFAULT_GATE_REPORT_PATH = "output/nuisance_gate_report.json"
UNKNOWN_SERVER_EXIT = 2
REFUSED_EXIT = 3
CRASHED_EXIT = 4


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
    gate = commands.add_parser(
        "gate", help="audit the admitted acceptance servers and compare them to their baselines"
    )
    _add_gate_arguments(gate)
    return parser


def _add_gate_arguments(gate: argparse.ArgumentParser) -> None:
    gate.set_defaults(command=_gate)
    gate.add_argument("--record-baseline", action="store_true")
    gate.add_argument("--runs", type=positive_int, default=NUISANCE_GATE_RUNS)
    gate.add_argument("--concurrency", type=positive_int, default=NUISANCE_CONCURRENCY)
    gate.add_argument(
        "--server", action="append", default=[], help="restrict the gate set, repeatable"
    )
    gate.add_argument("--report", type=Path, default=Path(DEFAULT_GATE_REPORT_PATH))
    gate.add_argument("--census", type=Path, default=CENSUS_PATH)
    gate.add_argument("--admission", type=Path, default=ADMISSION_PATH)


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
    write_dossier(census, args.server, args.out, args.backend)
    print(f"Admission dossier for {args.server} written to {args.out}")
    return 0


def _run(args: argparse.Namespace) -> int:
    _refuse_tracing()
    conditions = load_conditions(CONDITIONS_PATH)
    census = load_census(args.census)
    admission = _admission(args.admission, census)
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


def _admission(path: Path, census: HoldoutCensus) -> NuisanceAdmission | None:
    try:
        return load_admission(path, census)
    except FileNotFoundError:
        return None


def _gate(args: argparse.Namespace) -> int:
    census = load_census(args.census)
    admission = _admission(args.admission, census)
    current = current_acceptance_servers(census)
    servers = [] if admission is None else gate_servers(admission, current)
    if admission is None or not servers:
        _print_empty_gate(admission, current)
        return 0
    gate_set = [server.server_package for server in servers]
    unknown = [package for package in args.server if package not in gate_set]
    if unknown:
        print(
            f"unknown gate server: {', '.join(unknown)} (gate set: {', '.join(gate_set)})",
            file=sys.stderr,
        )
        return UNKNOWN_SERVER_EXIT
    try:
        return _run_gate(args, admission, current)
    except Refused:
        raise
    except Exception:
        traceback.print_exc()
        return CRASHED_EXIT


def _print_empty_gate(admission: NuisanceAdmission | None, current: set[str]) -> None:
    outside = [] if admission is None else outside_gate(admission, current)
    if not outside:
        print("no acceptance server is admitted")
        return
    print("no admitted acceptance server can run in the gate")
    for server in outside:
        print(f"- {server.server_package}: {server.reason}")


def _run_gate(args: argparse.Namespace, admission: NuisanceAdmission, current: set[str]) -> int:
    tree = read_tree()
    options = _gate_options(args, gate_servers(admission, current))
    session = asyncio.run(run_gate(options, default_harness(options.conditions, args.concurrency)))
    report = NuisanceGateReport(
        conditions=options.conditions,
        commit=tree.commit,
        dirty=tree.dirty,
        concurrency=args.concurrency,
        servers=server_lines(session, options.servers),
        not_run=session.not_run,
        not_admitted=not_admitted(admission, current),
        outside_gate=outside_gate(admission, current),
        orphans=session.orphans,
        gate=session.gate,
        written=[f"{w.server_package}: recorded ({w.status.value})" for w in session.written],
        recording_refused=session.recording_refused,
    )
    markdown = render_gate_markdown(report)
    _write_report(args.report, report, markdown)
    export_nuisance_gate_judged_cases(session.audits, args.report)
    print(markdown)
    _print_baselines(session)
    return session.exit_code


def _gate_options(args: argparse.Namespace, servers: list[AdmittedServer]) -> NuisanceGateOptions:
    return NuisanceGateOptions(
        servers=[s for s in servers if not args.server or s.server_package in args.server],
        gate_packages=frozenset(server.server_package for server in servers),
        conditions=gate_conditions(load_settings(), load_conditions(CONDITIONS_PATH), args.runs),
        record_baseline=args.record_baseline,
    )


_NEXT_STEP = {
    BaselineStatus.EXPLORATORY: (
        "Run gate --record-baseline again now, at this commit and on these images, to confirm."
    ),
    BaselineStatus.CONFIRMED: "Commit evals/baselines/nuisance/ by hand.",
}


def _print_baselines(session: NuisanceGateSession) -> None:
    for orphan in session.orphans:
        print(f"Orphaned baseline file, not compared: {orphan}")
    for written in session.written:
        path = NUISANCE_GATE_BASELINE_DIRECTORY / baseline_file_name(written.server_package)
        print(f"Baseline recorded ({written.status.value}) to {path}.")
        if written.leaves_gated_set:
            print(f"  {written.server_package} leaves the gated set.")
    for status in dict.fromkeys(written.status for written in session.written):
        print(_NEXT_STEP[status])
    for reason in session.recording_refused:
        print(f"Recording refused: {reason}")


def _refuse_tracing() -> None:
    if tracing_enabled():
        raise Refused(
            "nuisance run refused",
            ["LANGSMITH_TRACING or LANGCHAIN_TRACING_V2 is set; a nuisance run keeps no trace"],
        )


def _write_report(path: Path, report: BaseModel, markdown: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2))
    path.with_suffix(".md").write_text(markdown)


if __name__ == "__main__":
    sys.exit(main())
