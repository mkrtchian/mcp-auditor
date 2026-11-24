"""What the nuisance subcommands share: the walk record path, the admission they read, the
population a run audits, their default concurrency and their exit codes."""

import argparse
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from evals.cve.census.census import CENSUS_PATH, load_census
from evals.cve.nuisance.admission.admission import ADMISSION_PATH, NuisanceAdmission
from evals.cve.nuisance.admission.admission_load import load_admission
from evals.cve.nuisance.admission.walk import acceptance_target_servers, reached_servers
from evals.cve.nuisance.admission.walk_record import WalkInputs, load_walk_record
from evals.cve.nuisance.holdout_servers import RunPopulation, run_population
from evals.eval_session import Refused
from evals.repository import REPO_ROOT

WALK_RECORD_PATH = REPO_ROOT / "evals" / "nuisance_walk_record.json"
NUISANCE_CONCURRENCY = 6
UNKNOWN_SERVER_EXIT = 2
CRASHED_EXIT = 4


def add_committed_input_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--census", type=Path, default=CENSUS_PATH)
    parser.add_argument("--walk-record", type=Path, default=WALK_RECORD_PATH)
    parser.add_argument("--admission", type=Path, default=ADMISSION_PATH)


def committed_run_population(
    census_path: Path, walk_record_path: Path, admission_path: Path
) -> tuple[WalkInputs, RunPopulation] | None:
    """None when the admission is absent or admits no server."""
    with malformed_input_refused():
        walk_inputs = committed_walk_inputs(census_path, walk_record_path)
        admission = committed_admission(admission_path, walk_inputs)
        if admission is None or not admission.servers:
            return None
        population = run_population(
            reached_servers(walk_inputs), admission, acceptance_target_servers(walk_inputs)
        )
    return walk_inputs, population


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


def committed_walk_inputs(census_path: Path, record_path: Path) -> WalkInputs:
    census = load_census(census_path)
    try:
        return load_walk_record(record_path, census)
    except FileNotFoundError as error:
        raise Refused(
            "Refused: the nuisance walk record is not committed.", [str(error)]
        ) from error


def committed_admission(path: Path, walk_inputs: WalkInputs) -> NuisanceAdmission | None:
    try:
        return load_admission(path, walk_inputs)
    except FileNotFoundError:
        return None
