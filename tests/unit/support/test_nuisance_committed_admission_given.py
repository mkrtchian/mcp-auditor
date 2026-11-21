from functools import cache

from evals.cve.census.census import CENSUS_PATH, load_census
from evals.cve.nuisance.admission.admission import ADMISSION_PATH, NuisanceAdmission, load_admission
from evals.cve.nuisance.admission.walk_record import WalkInputs, load_walk_record
from evals.cve.nuisance.commands import WALK_RECORD_PATH


@cache
def the_committed_walk_inputs() -> WalkInputs:
    return load_walk_record(WALK_RECORD_PATH, load_census(CENSUS_PATH))


@cache
def the_committed_admission() -> NuisanceAdmission:
    return load_admission(ADMISSION_PATH, the_committed_walk_inputs())
