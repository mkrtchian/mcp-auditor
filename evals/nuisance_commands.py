"""What the nuisance subcommands share: the census path, the admission they read, the report files
they write and their exit codes."""

from pathlib import Path

from pydantic import BaseModel

from evals.holdout_census import HoldoutCensus
from evals.honeypots import REPO_ROOT
from evals.nuisance_admission import NuisanceAdmission, load_admission

CENSUS_PATH = REPO_ROOT / "evals" / "holdout_census.json"
UNKNOWN_SERVER_EXIT = 2
REFUSED_EXIT = 3
CRASHED_EXIT = 4


def committed_admission(path: Path, census: HoldoutCensus) -> NuisanceAdmission | None:
    try:
        return load_admission(path, census)
    except FileNotFoundError:
        return None


def write_report(path: Path, report: BaseModel, markdown: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2))
    path.with_suffix(".md").write_text(markdown)
