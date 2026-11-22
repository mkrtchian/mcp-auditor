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
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from evals import eval_display as display
from evals.cve.census.census import CENSUS_PATH
from evals.cve.detection.draw_record import governing_steps
from evals.cve.nuisance.admission.admission import ADMISSION_PATH
from evals.cve.nuisance.admission.admission_walk import addition_entries
from evals.cve.nuisance.admission.dossier import write_dossier
from evals.cve.nuisance.admission.re_admission_dossier import (
    re_admission_plan,
    write_re_admission_dossier,
)
from evals.cve.nuisance.admission.walk import NuisanceServer, nuisance_population
from evals.cve.nuisance.commands import (
    CRASHED_EXIT,
    REFUSED_EXIT,
    WALK_RECORD_PATH,
    committed_admission,
    committed_walk_inputs,
    malformed_input_refused,
)
from evals.cve.nuisance.fix_check_command import FixCheckCommandDeps, add_fix_check_arguments
from evals.cve.nuisance.gate.gate_command import GateCommandDeps, add_gate_arguments
from evals.cve.nuisance.holdout_run_command import RunCommandDeps, add_run_arguments
from evals.cve.nuisance.vet_command import VetCommandDeps, add_vet_arguments
from evals.cve.provider_errors import ProviderFatal, describe_provider_error
from evals.eval_session import Refused
from evals.metrics import quiet_throttle_waits
from mcp_auditor.adapters.log_redaction import silenced_stdio_logging


@dataclass(frozen=True)
class NuisanceCommandDeps:
    run: RunCommandDeps = field(default_factory=RunCommandDeps)
    fix_check: FixCheckCommandDeps = field(default_factory=FixCheckCommandDeps)
    gate: GateCommandDeps = field(default_factory=GateCommandDeps)
    vet: VetCommandDeps = field(default_factory=VetCommandDeps)


def main(argv: Sequence[str] | None = None, deps: NuisanceCommandDeps | None = None) -> int:
    quiet_throttle_waits()
    args = _parser(deps or NuisanceCommandDeps()).parse_args(argv)
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


def _parser(deps: NuisanceCommandDeps) -> argparse.ArgumentParser:
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
    add_run_arguments(
        commands.add_parser(
            "run", help="audit the admitted servers and report the holdout nuisance rate"
        ),
        deps.run,
    )
    add_fix_check_arguments(
        commands.add_parser(
            "fix-check", help="rebuild and reproduce each fix-check fixture against the admission"
        ),
        deps.fix_check,
    )
    add_gate_arguments(
        commands.add_parser(
            "gate",
            help="audit the admitted nuisance acceptance servers and compare them to their"
            " baselines",
        ),
        deps.gate,
    )
    add_vet_arguments(
        commands.add_parser(
            "vet", help="rebuild the run's images and make each audited server's benign calls"
        ),
        deps.vet,
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


def _walk_line(server: NuisanceServer, outcomes: Mapping[str, str]) -> str:
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
    write_re_admission_dossier(re_admission_plan(walk_inputs, admission, args.server), args.out)
    print(f"Re-admission dossier for {args.server} written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
