"""The files a holdout or nuisance run writes: its report, the report's markdown and the run
result beside them. The result is written before the report is built, so an error building it
loses no paid run, and a run never overwrites any of the three."""

import dataclasses
import json
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from evals import holdout_results, nuisance_results
from evals.eval_session import Refused
from evals.holdout_results import HoldoutRunResult
from evals.nuisance_results import NuisanceRunResult


def refuse_existing_report(report: Path, title: str) -> None:
    existing = [
        path for path in (report, report.with_suffix(".md"), result_path(report)) if path.exists()
    ]
    if existing:
        raise Refused(
            title,
            [
                f"{path} exists: a run never overwrites it, pass another --report"
                for path in existing
            ],
        )


def write_result(report: Path, run: HoldoutRunResult | NuisanceRunResult) -> None:
    path = result_path(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dataclasses.asdict(run), default=str, indent=2))


@contextmanager
def partial_result_kept(report: Path) -> Generator[None]:
    """Writes the partial result of a run stopped by an exception, then raises that exception."""
    try:
        yield
    except (holdout_results.RunInterrupted, nuisance_results.RunInterrupted) as interrupted:
        write_result(report, interrupted.partial)
        raise interrupted.cause  # noqa: B904


def result_path(report: Path) -> Path:
    return report.with_suffix(".result.json")
