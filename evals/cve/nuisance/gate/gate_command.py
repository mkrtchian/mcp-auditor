"""The `gate` subcommand of run_nuisance: audit the counted tools of each admitted
nuisance acceptance server and compare it to its baseline under `evals/baselines/nuisance/`.
`--no-tools-filter` audits every tool in a report-only run, which gates nothing and records no
baseline."""

import argparse
import asyncio
import dataclasses
import functools
import traceback
from collections.abc import Sequence
from pathlib import Path

from rich.markup import escape
from rich.progress import Progress
from rich.text import Text

from evals.cli_arguments import positive_int
from evals.cve.audit_progress import AuditProgress
from evals.cve.file_baselines import next_recording_step
from evals.cve.nuisance.admission.admission import AdmittedServer
from evals.cve.nuisance.admission.unrecorded import refuse_unrecorded
from evals.cve.nuisance.admission.walk import nuisance_acceptance_servers
from evals.cve.nuisance.commands import (
    CRASHED_EXIT,
    NUISANCE_CONCURRENCY,
    UNKNOWN_SERVER_EXIT,
    add_committed_input_arguments,
    committed_admission,
    committed_walk_inputs,
    malformed_input_refused,
)
from evals.cve.nuisance.gate.gate_baseline import (
    NUISANCE_GATE_BASELINE_DIRECTORY,
    NUISANCE_GATE_RUNS,
    NuisanceGateConditions,
    baseline_file_name,
    gate_conditions,
)
from evals.cve.nuisance.gate.gate_command_deps import GateCommandDeps, GateSessionRunner
from evals.cve.nuisance.gate.gate_console import print_nuisance_gate_summary
from evals.cve.nuisance.gate.gate_judged_cases_export import export_nuisance_gate_judged_cases
from evals.cve.nuisance.gate.gate_report import (
    NuisanceGateReport,
    render_markdown,
    server_lines,
)
from evals.cve.nuisance.gate.gate_servers import (
    GateServers,
    gate_servers,
    print_empty_gate,
    print_unknown_gate_servers,
)
from evals.cve.nuisance.gate.gate_session_model import (
    NuisanceGateHarness,
    NuisanceGateOptions,
    NuisanceGateSession,
)
from evals.cve.run_files import write_report
from evals.eval_display import console
from evals.eval_session import RECORDING_REFUSED, Refused
from evals.model_provider_errors import ProviderFatal

DEFAULT_GATE_REPORT_PATH = "output/nuisance_gate_report.json"
_BASELINES = "evals/baselines/nuisance/"
_RECORD_COMMAND = "uv run python -m evals.run_nuisance gate --record-baseline"
RECORD_WITHOUT_TOOLS_FILTER = (
    "--record-baseline cannot run --no-tools-filter: a baseline records the counted tools it gates"
)


def add_gate_arguments(gate_parser: argparse.ArgumentParser, deps: GateCommandDeps) -> None:
    gate_parser.set_defaults(command=functools.partial(gate, deps=deps))
    gate_parser.add_argument("--record-baseline", action="store_true")
    gate_parser.add_argument(
        "--no-tools-filter",
        action="store_true",
        help="audit every tool of each server, report only: no baseline read, nothing gated",
    )
    gate_parser.add_argument("--runs", type=positive_int, default=NUISANCE_GATE_RUNS)
    gate_parser.add_argument("--concurrency", type=positive_int, default=NUISANCE_CONCURRENCY)
    gate_parser.add_argument(
        "--server", action="append", default=[], help="restrict the gate set, repeatable"
    )
    gate_parser.add_argument("--report", type=Path, default=Path(DEFAULT_GATE_REPORT_PATH))
    add_committed_input_arguments(gate_parser)


def gate(args: argparse.Namespace, deps: GateCommandDeps) -> int:
    if args.record_baseline and args.no_tools_filter:
        raise Refused(RECORDING_REFUSED, [RECORD_WITHOUT_TOOLS_FILTER])
    with malformed_input_refused():
        walk_inputs = committed_walk_inputs(args.census, args.walk_record)
        admission = committed_admission(args.admission, walk_inputs)
    servers = gate_servers(admission, nuisance_acceptance_servers(walk_inputs))
    if not servers.audited:
        print_empty_gate(servers.outside_gate)
        return 0
    gate_set = [server.server_package for server in servers.audited]
    unknown = [package for package in args.server if package not in gate_set]
    if unknown:
        print_unknown_gate_servers(unknown, gate_set)
        return UNKNOWN_SERVER_EXIT
    refuse_unrecorded(_selected(servers.audited, args.server), "nuisance gate refused")
    try:
        return _run_gate(args, servers, deps)
    except (Refused, ProviderFatal):
        raise
    except Exception:
        traceback.print_exc()
        return CRASHED_EXIT


def _selected(servers: list[AdmittedServer], packages: list[str]) -> list[AdmittedServer]:
    return [server for server in servers if not packages or server.server_package in packages]


def _run_gate(args: argparse.Namespace, servers: GateServers, deps: GateCommandDeps) -> int:
    conditions = gate_conditions(deps.settings(), deps.conditions(), args.runs)
    if args.no_tools_filter:
        conditions = conditions.model_copy(update={"tools_filtered": False})
    options = _gate_options(args, servers.audited, conditions)
    harness = deps.harness(options.conditions, args.concurrency)
    tree = harness.read_tree()
    session = _tracked_gate(options, harness, deps.run_gate)
    report = NuisanceGateReport(
        conditions=options.conditions,
        commit=tree.commit,
        dirty=tree.dirty,
        concurrency=args.concurrency,
        throttled_requests=session.throttled_requests,
        servers=server_lines(session, options.servers),
        not_run=session.not_run,
        not_admitted=servers.not_admitted,
        outside_gate=servers.outside_gate,
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
    options: NuisanceGateOptions,
    harness: NuisanceGateHarness,
    run: GateSessionRunner,
) -> NuisanceGateSession:
    with Progress(console=console) as bar:
        progress = AuditProgress(bar)
        tracked = dataclasses.replace(
            harness, audit=progress.tracked(harness.audit), announce_audits=progress.announce
        )
        return asyncio.run(run(options, tracked))


def _gate_options(
    args: argparse.Namespace, servers: list[AdmittedServer], conditions: NuisanceGateConditions
) -> NuisanceGateOptions:
    return NuisanceGateOptions(
        servers=_selected(servers, args.server),
        gate_packages=frozenset(server.server_package for server in servers),
        conditions=conditions,
        record_baseline=args.record_baseline,
        report_only=args.no_tools_filter,
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
    command = " ".join([_RECORD_COMMAND, *recorded_flags])
    for status in dict.fromkeys(written.status for written in session.written):
        console.print(Text(next_recording_step(status, command, _BASELINES)))
    for reason in session.recording_refused:
        console.print(Text(f"Recording refused: {reason}"))


def _recorded_flags(args: argparse.Namespace) -> list[str]:
    # The confirming recording refuses on a condition mismatch: it repeats the server filter and
    # the run count, the one flag that enters the recorded conditions.
    flags = [f"--server {package}" for package in args.server]
    if args.runs != NUISANCE_GATE_RUNS:
        flags.append(f"--runs {args.runs}")
    return flags
