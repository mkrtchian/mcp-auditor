"""Holdout-specific commands, kept out of run_census (the census) and run_cve_benchmark (the
benchmark). No LLM, no network.
"""

import argparse
import sys
from collections import Counter
from collections.abc import Sequence
from datetime import date
from pathlib import Path

from evals import calibration_dossier
from evals import eval_display as display
from evals.census_draw import Side
from evals.eval_session import Refused
from evals.holdout_census import load_census
from evals.holdout_draw import draw_order
from evals.honeypots import REPO_ROOT

CENSUS_PATH = REPO_ROOT / "evals" / "holdout_census.json"
REFUSED_EXIT = 3


def main(argv: Sequence[str] | None = None) -> int:
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
    parser = argparse.ArgumentParser(description="Holdout draw commands.")
    commands = parser.add_subparsers(required=True)
    draw = commands.add_parser("draw-order", help="print the draw order for the maintainer to walk")
    draw.set_defaults(command=_draw_order)
    draw.add_argument("--census", type=Path, default=CENSUS_PATH)
    draw.add_argument("--cutoff", type=date.fromisoformat, required=True)
    draw.add_argument("--cutoff-type", default=None)
    draw.add_argument("--cutoff-note", default=None)
    dossier = commands.add_parser(
        "calibration-dossier", help="write the isolated calibration kit for one candidate"
    )
    dossier.set_defaults(command=_calibration_dossier)
    dossier.add_argument("--census", type=Path, default=CENSUS_PATH)
    dossier.add_argument("--cve", required=True)
    dossier.add_argument("--out", type=Path, required=True)
    return parser


def _draw_order(args: argparse.Namespace) -> int:
    census = load_census(args.census)
    entries = draw_order(census, args.cutoff)
    print(f"Cutoff {args.cutoff} ({args.cutoff_type or 'unspecified'})")
    if args.cutoff_note:
        print(f"Note: {args.cutoff_note}")
    print(f"{len(entries)} candidates in draw order:")
    for entry in entries:
        print(f"  {entry.digest[:12]}  {entry.identifier}  {entry.side}  {entry.disclosure_date}")
    tally = Counter(entry.side for entry in entries)
    for side in Side:
        print(f"{side}: {tally[side]}")
    return 0


def _calibration_dossier(args: argparse.Namespace) -> int:
    census = load_census(args.census)
    calibration_dossier.write_kit(census, args.cve, args.out)
    print(f"Calibration kit for {args.cve} written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
