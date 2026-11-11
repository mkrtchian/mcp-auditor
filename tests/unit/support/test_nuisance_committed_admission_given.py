from functools import cache

from evals.cve.census.census import load_census
from evals.cve.nuisance.commands import CENSUS_PATH, WALK_RECORD_PATH
from evals.cve.nuisance.walk_record import WalkInputs, load_walk_record
from evals.nuisance_admission import ADMISSION_PATH, NuisanceAdmission, load_admission


@cache
def the_committed_census() -> WalkInputs:
    return load_walk_record(WALK_RECORD_PATH, load_census(CENSUS_PATH))


@cache
def the_committed_admission() -> NuisanceAdmission:
    return load_admission(ADMISSION_PATH, the_committed_census())
