from evals.cve.census.census import CENSUS_PATH, load_census


def test_the_committed_census_loads():
    assert load_census(CENSUS_PATH).flaws
