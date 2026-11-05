from functools import cache

from evals.holdout_census import load_census
from evals.nuisance_admission import ADMISSION_PATH, NuisanceAdmission, load_admission
from evals.nuisance_commands import CENSUS_PATH, WALK_RECORD_PATH
from evals.nuisance_walk_record import NuisanceCensus, load_walk_record


@cache
def the_committed_census() -> NuisanceCensus:
    return load_walk_record(WALK_RECORD_PATH, load_census(CENSUS_PATH))


@cache
def the_committed_admission() -> NuisanceAdmission:
    return load_admission(ADMISSION_PATH, the_committed_census())
