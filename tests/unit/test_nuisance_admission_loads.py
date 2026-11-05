from evals.holdout_census import load_census
from evals.nuisance_admission import ADMISSION_PATH, load_admission
from evals.nuisance_commands import WALK_RECORD_PATH
from evals.nuisance_walk_record import load_walk_record
from evals.run_census import CENSUS_PATH


def test_the_committed_admission_loads():
    load_admission(ADMISSION_PATH, load_walk_record(WALK_RECORD_PATH, load_census(CENSUS_PATH)))
