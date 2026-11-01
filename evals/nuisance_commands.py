"""What the nuisance subcommands share: the census and walk record paths, the admission they read,
the report files they write and their exit codes."""

from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from pydantic import BaseModel

from evals.eval_session import Refused
from evals.holdout_census import load_census
from evals.honeypots import REPO_ROOT
from evals.nuisance_admission import NuisanceAdmission, load_admission
from evals.nuisance_walk_record import NuisanceCensus, load_walk_record

CENSUS_PATH = REPO_ROOT / "evals" / "holdout_census.json"
WALK_RECORD_PATH = REPO_ROOT / "evals" / "nuisance_walk_record.json"
UNKNOWN_SERVER_EXIT = 2
REFUSED_EXIT = 3
CRASHED_EXIT = 4


@contextmanager
def malformed_input_refused() -> Generator[None]:
    """Wraps the reading of the census, the walk record and the admission only: a malformed one
    must not read as success, and a ValueError raised later is a crash."""
    try:
        yield
    except ValueError as error:
        raise Refused(
            "Refused: the census, the walk record or the admission is malformed.", [str(error)]
        ) from error


def committed_nuisance_census(census_path: Path, record_path: Path) -> NuisanceCensus:
    census = load_census(census_path)
    try:
        return load_walk_record(record_path, census)
    except FileNotFoundError as error:
        raise Refused(
            "Refused: the nuisance walk record is not committed.", [str(error)]
        ) from error


def committed_admission(path: Path, nuisance_census: NuisanceCensus) -> NuisanceAdmission | None:
    try:
        return load_admission(path, nuisance_census)
    except FileNotFoundError:
        return None


def write_report(path: Path, report: BaseModel, markdown: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2))
    path.with_suffix(".md").write_text(markdown)
