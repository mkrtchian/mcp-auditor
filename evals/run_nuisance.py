"""Nuisance-specific commands, kept out of run_census, run_cve_benchmark and run_holdout.

`walk` prints the servers the holdout walk reached, each with its reaching flaw and the flaws
that set its version, for the maintainer to admit (no LLM, no network). `nuisance-dossier` writes
the isolated admission dossier for one server (no LLM; the fix-check driver it ships needs
Docker). No server is admitted yet.
"""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from evals import eval_display as display
from evals.eval_session import Refused
from evals.holdout_census import load_census
from evals.honeypots import REPO_ROOT
from evals.metrics import quiet_throttle_waits
from evals.nuisance_dossier import write_dossier
from evals.nuisance_walk import nuisance_population

CENSUS_PATH = REPO_ROOT / "evals" / "holdout_census.json"
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
        # A malformed census must not read as success.
        display.print_refusal("Refused: the census is malformed.", [str(error)])
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


if __name__ == "__main__":
    sys.exit(main())
