"""Holdout-specific commands, kept out of run_census (the census) and run_cve_benchmark (the
benchmark). The draw-order and calibration-dossier scaffolding runs with no LLM and no network;
the `run` command audits the drawn targets, so it needs Docker and an LLM key.
"""

import argparse
import asyncio
import sys
from collections import Counter
from collections.abc import Sequence
from datetime import date
from pathlib import Path

from evals import calibration_dossier, holdout_targets
from evals import eval_display as display
from evals.census_draw import Side
from evals.concurrency import positive_int
from evals.cve_places import HOLDOUT_PLACES, load_places
from evals.eval_runs import tracing_enabled
from evals.eval_session import Refused, last_commit
from evals.holdout_census import load_census
from evals.holdout_conditions import CONDITIONS_PATH, load_conditions
from evals.holdout_draw import draw_order
from evals.holdout_report import HoldoutReport, build_report, render_markdown
from evals.holdout_run import HOLDOUT_RUNS, run_holdout
from evals.honeypots import REPO_ROOT
from mcp_auditor.config import load_settings

CENSUS_PATH = REPO_ROOT / "evals" / "holdout_census.json"
DEFAULT_REPORT_PATH = "output/holdout_report.json"
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
    run = commands.add_parser("run", help="audit the drawn targets and report the capability")
    run.set_defaults(command=_run)
    run.add_argument("--report", type=Path, default=Path(DEFAULT_REPORT_PATH))
    run.add_argument("--runs", type=positive_int, default=None, help="default 3, lowerable to 1")
    run.add_argument("--concurrency", type=positive_int, default=6)
    run.add_argument("--census", type=Path, default=CENSUS_PATH)
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


def _run(args: argparse.Namespace) -> int:
    _refuse_tracing()
    conditions = load_conditions(CONDITIONS_PATH)
    if not holdout_targets.HOLDOUT_TARGETS:
        print("no holdout target is drawn")
        return 0
    settings = load_settings()
    model_ids = list(dict.fromkeys([settings.resolve_model(), settings.resolve_judge_model()]))
    conditions.require_ready(model_ids)
    census = load_census(args.census)
    disclosure_dates = {flaw.identifier: flaw.disclosure_date for flaw in census.flaws}
    run = asyncio.run(
        run_holdout(
            holdout_targets.HOLDOUT_TARGETS,
            disclosure_dates,
            conditions,
            settings,
            load_places(HOLDOUT_PLACES),
            last_commit(args.census),
            runs=args.runs if args.runs is not None else HOLDOUT_RUNS,
            concurrency=args.concurrency,
        )
    )
    report = build_report(run, conditions.run_cutoff(model_ids))
    markdown = render_markdown(report)
    _write_report(args.report, report, markdown)
    print(markdown)
    return 0


def _refuse_tracing() -> None:
    if tracing_enabled():
        raise Refused(
            "holdout run refused",
            ["LANGSMITH_TRACING or LANGCHAIN_TRACING_V2 is set; a holdout run keeps no trace"],
        )


def _write_report(path: Path, report: HoldoutReport, markdown: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2))
    path.with_suffix(".md").write_text(markdown)


if __name__ == "__main__":
    sys.exit(main())
