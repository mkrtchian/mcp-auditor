"""The `gate` subcommand of run_nuisance: audit the admitted nuisance acceptance servers and
compare each to its baseline under `evals/baselines/nuisance/`."""

import argparse
import asyncio
import dataclasses
import sys
import traceback
from collections.abc import Sequence
from pathlib import Path

from rich.markup import escape
from rich.progress import Progress
from rich.text import Text

from evals.baseline import BaselineStatus
from evals.concurrency import positive_int
from evals.cve.audit_progress import AuditProgress
from evals.cve.holdout_conditions import CONDITIONS_PATH, load_conditions
from evals.cve.nuisance.commands import (
    CENSUS_PATH,
    CRASHED_EXIT,
    UNKNOWN_SERVER_EXIT,
    WALK_RECORD_PATH,
    committed_admission,
    committed_walk_inputs,
    malformed_input_refused,
    write_report,
)
from evals.cve.nuisance.gate_baseline import (
    NUISANCE_GATE_BASELINE_DIRECTORY,
    NUISANCE_GATE_RUNS,
    baseline_file_name,
    gate_conditions,
)
from evals.cve.nuisance.gate_console import print_nuisance_gate_summary
from evals.cve.nuisance.gate_report import NuisanceGateReport, render_markdown, server_lines
from evals.cve.nuisance.gate_session import (
    default_harness,
    gate_servers,
    not_admitted,
    outside_gate,
    run_gate,
)
from evals.cve.nuisance.gate_session_model import (
    NuisanceGateHarness,
    NuisanceGateOptions,
    NuisanceGateSession,
)
from evals.cve.nuisance.run import NUISANCE_CONCURRENCY
from evals.cve.nuisance.unrecorded import refuse_unrecorded
from evals.cve.nuisance.walk import nuisance_acceptance_servers
from evals.eval_display import console
from evals.eval_session import Refused
from evals.export import export_nuisance_gate_judged_cases
from evals.nuisance_admission import ADMISSION_PATH, AdmittedServer, NuisanceAdmission
from mcp_auditor.config import load_settings

DEFAULT_GATE_REPORT_PATH = "output/nuisance_gate_report.json"
_BASELINES = "evals/baselines/nuisance/"
_RECORD_COMMAND = "uv run python -m evals.run_nuisance gate --record-baseline"


def add_gate_arguments(gate_parser: argparse.ArgumentParser) -> None:
    gate_parser.set_defaults(command=gate)
    gate_parser.add_argument("--record-baseline", action="store_true")
    gate_parser.add_argument("--runs", type=positive_int, default=NUISANCE_GATE_RUNS)
    gate_parser.add_argument("--concurrency", type=positive_int, default=NUISANCE_CONCURRENCY)
    gate_parser.add_argument(
        "--server", action="append", default=[], help="restrict the gate set, repeatable"
    )
    gate_parser.add_argument("--report", type=Path, default=Path(DEFAULT_GATE_REPORT_PATH))
    gate_parser.add_argument("--census", type=Path, default=CENSUS_PATH)
    gate_parser.add_argument("--walk-record", type=Path, default=WALK_RECORD_PATH)
    gate_parser.add_argument("--admission", type=Path, default=ADMISSION_PATH)


def gate(args: argparse.Namespace) -> int:
    with malformed_input_refused():
        walk_inputs = committed_walk_inputs(args.census, args.walk_record)
        admission = committed_admission(args.admission, walk_inputs)
    current = nuisance_acceptance_servers(walk_inputs)
    servers = [] if admission is None else gate_servers(admission, current)
    if admission is None or not servers:
        _print_empty_gate(admission, current)
        return 0
    gate_set = [server.server_package for server in servers]
    unknown = [package for package in args.server if package not in gate_set]
    if unknown:
        _print_unknown(unknown, gate_set)
        return UNKNOWN_SERVER_EXIT
    refuse_unrecorded(_selected(servers, args.server), "nuisance gate refused")
    try:
        return _run_gate(args, admission, current)
    except Refused:
        raise
    except Exception:
        traceback.print_exc()
        return CRASHED_EXIT


def _print_unknown(unknown: list[str], gate_set: list[str]) -> None:
    print(
        f"unknown gate server: {', '.join(unknown)} (gate set: {', '.join(gate_set)})",
        file=sys.stderr,
    )


def _selected(servers: list[AdmittedServer], packages: list[str]) -> list[AdmittedServer]:
    return [server for server in servers if not packages or server.server_package in packages]


def _print_empty_gate(admission: NuisanceAdmission | None, current: set[str]) -> None:
    outside = [] if admission is None else outside_gate(admission, current)
    if not outside:
        print("no nuisance acceptance server is admitted")
        return
    print("no admitted nuisance acceptance server can run in the gate")
    for server in outside:
        print(f"- {server.server_package}: {server.reason}")


def _run_gate(args: argparse.Namespace, admission: NuisanceAdmission, current: set[str]) -> int:
    options = _gate_options(args, gate_servers(admission, current))
    harness = default_harness(options.conditions, args.concurrency)
    tree = harness.read_tree()
    session = _tracked_gate(options, harness)
    report = NuisanceGateReport(
        conditions=options.conditions,
        commit=tree.commit,
        dirty=tree.dirty,
        concurrency=args.concurrency,
        throttled_requests=session.throttled_requests,
        servers=server_lines(session, options.servers),
        not_run=session.not_run,
        not_admitted=not_admitted(admission, current),
        outside_gate=outside_gate(admission, current),
        orphans=session.orphans,
        gate=session.gate,
        written=[f"{w.server_package}: recorded ({w.status.value})" for w in session.written],
        recording_refused=session.recording_refused,
    )
    write_report(args.report, report, render_markdown(report))
    export_nuisance_gate_judged_cases(session.audits, args.report)
    print_nuisance_gate_summary(report, args.report)
    _print_baselines(session, _recorded_flags(args))
    return session.exit_code


def _tracked_gate(
    options: NuisanceGateOptions, harness: NuisanceGateHarness
) -> NuisanceGateSession:
    with Progress(console=console) as bar:
        progress = AuditProgress(bar)
        tracked = dataclasses.replace(
            harness, audit=progress.tracked(harness.audit), announce_audits=progress.announce
        )
        return asyncio.run(run_gate(options, tracked))


def _gate_options(args: argparse.Namespace, servers: list[AdmittedServer]) -> NuisanceGateOptions:
    return NuisanceGateOptions(
        servers=_selected(servers, args.server),
        gate_packages=frozenset(server.server_package for server in servers),
        conditions=gate_conditions(load_settings(), load_conditions(CONDITIONS_PATH), args.runs),
        record_baseline=args.record_baseline,
    )


def _print_baselines(session: NuisanceGateSession, recorded_flags: Sequence[str]) -> None:
    for orphan in session.orphans:
        console.print(f"[yellow]Orphaned baseline file, not compared:[/yellow] {escape(orphan)}")
    for written in session.written:
        path = NUISANCE_GATE_BASELINE_DIRECTORY / baseline_file_name(written.server_package)
        console.print(Text(f"Baseline recorded ({written.status.value}) to {path}.", style="green"))
        if written.leaves_gated_set:
            console.print(Text(f"  {written.server_package} leaves the gated set."))
    # A recording can confirm some files and start others, and each status has its next step.
    for status in dict.fromkeys(written.status for written in session.written):
        console.print(Text(_next_step(status, recorded_flags)))
    for reason in session.recording_refused:
        console.print(Text(f"Recording refused: {reason}"))


def _next_step(status: BaselineStatus, recorded_flags: Sequence[str]) -> str:
    if status == BaselineStatus.CONFIRMED:
        return f"Commit {_BASELINES} by hand."
    command = " ".join([_RECORD_COMMAND, *recorded_flags])
    return (
        f"Run {command} again now, at this commit and on these images, to confirm it. "
        f"Commit {_BASELINES} by hand once confirmed."
    )


def _recorded_flags(args: argparse.Namespace) -> list[str]:
    # The confirming recording refuses on a condition mismatch: it repeats the server filter and
    # the run count, the one flag that enters the recorded conditions.
    flags = [f"--server {package}" for package in args.server]
    if args.runs != NUISANCE_GATE_RUNS:
        flags.append(f"--runs {args.runs}")
    return flags
