from functools import cache

from evals.cve.census.census import CENSUS_PATH, load_census
from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.nuisance.admission.admission import ADMISSION_PATH, NuisanceAdmission
from evals.cve.nuisance.admission.admission_load import load_admission
from evals.cve.nuisance.admission.holdout_calibration_copies import copy_targets
from evals.cve.nuisance.admission.walk_record import WalkInputs, load_walk_record
from evals.cve.nuisance.commands import WALK_RECORD_PATH


@cache
def the_committed_admission() -> NuisanceAdmission:
    return load_admission(ADMISSION_PATH, the_committed_walk_inputs())


def the_copy_resolution() -> dict[str, str]:
    return copy_targets(
        [target.flaw_id for target in HOLDOUT_TARGETS], the_committed_walk_inputs().census.draw
    )


@cache
def the_committed_walk_inputs() -> WalkInputs:
    return load_walk_record(WALK_RECORD_PATH, load_census(CENSUS_PATH))
