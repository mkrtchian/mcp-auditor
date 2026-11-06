from evals.holdout_census import load_census
from evals.run_census import CENSUS_PATH


def the_census_drawn_identifiers() -> set[str]:
    draw = load_census(CENSUS_PATH).draw
    assert draw is not None, "the committed census carries no draw"
    return set(draw.drawn)
