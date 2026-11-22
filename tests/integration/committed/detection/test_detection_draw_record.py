from evals.cve.census.census import CENSUS_PATH, load_census


def test_the_committed_census_draw_validates_clean():
    # load_census runs draw_problems on a present draw and raises on any problem, so a clean load
    # with the draw present is the committed draw validating.
    assert load_census(CENSUS_PATH).draw is not None
