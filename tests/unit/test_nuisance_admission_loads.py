import pytest

from evals.holdout_census import load_census
from evals.nuisance_admission import ADMISSION_PATH, load_admission
from evals.run_census import CENSUS_PATH


def test_the_committed_admission_loads():
    if not ADMISSION_PATH.exists():
        pytest.skip("no admission committed yet")
    load_admission(ADMISSION_PATH, load_census(CENSUS_PATH))
