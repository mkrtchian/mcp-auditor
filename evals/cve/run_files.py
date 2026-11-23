"""The files a holdout run writes: its report, the report's markdown and the run result beside
them, the report write shared with the nuisance gate and the detection gate's command. The result
is written before the report is built, so an error building it loses no paid run, and a run never
overwrites any of the three."""

import dataclasses
import json
from collections.abc import Callable, Generator
from contextlib import contextmanager
from pathlib import Path

from pydantic import BaseModel

from evals.cve.detection.holdout_results import DetectionHoldoutRunResult
from evals.cve.nuisance.results import NuisanceHoldoutRunResult
from evals.eval_session import Refused


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


class RunInterrupted(Exception):
    """A run stopped by an exception out of one of its audits, with what had finished."""

    def __init__(
        self, partial: DetectionHoldoutRunResult | NuisanceHoldoutRunResult, cause: BaseException
    ) -> None:
        super().__init__(f"the run stopped on {type(cause).__name__}")
        self.partial = partial
        self.cause = cause


@contextmanager
def partial_result_kept(report: Path) -> Generator[None]:
    """Writes the partial result of a run stopped by an exception, then raises that exception."""
    try:
        yield
    except RunInterrupted as interrupted:
        write_result(report, interrupted.partial)
        raise interrupted.cause  # noqa: B904


def write_result(report: Path, run: DetectionHoldoutRunResult | NuisanceHoldoutRunResult) -> None:
    path = result_path(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dataclasses.asdict(run), default=str, indent=2))


def result_path(report: Path) -> Path:
    return report.with_suffix(".result.json")


type ReportWriter = Callable[[Path, BaseModel, str], None]


def write_report(path: Path, report: BaseModel, markdown: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2))
    path.with_suffix(".md").write_text(markdown)
