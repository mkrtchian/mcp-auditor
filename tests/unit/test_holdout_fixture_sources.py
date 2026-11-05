import pytest

import tests.unit.support.test_holdout_fixture_sources_then as then
from evals.census_draw import CalibrationCard
from evals.cve_targets import CVETarget
from evals.holdout_census import load_census
from evals.holdout_targets import HOLDOUT_TARGETS
from evals.run_census import CENSUS_PATH

_TARGETS = {target.cve_id: target for target in HOLDOUT_TARGETS}


def _drawn_cards() -> list[tuple[CalibrationCard, CVETarget]]:
    draw = load_census(CENSUS_PATH).draw
    cards = [] if draw is None else draw.cards
    return [(card, _TARGETS[card.flaw]) for card in cards if card.flaw in _TARGETS]


@pytest.mark.parametrize(
    ("card", "target"), _drawn_cards(), ids=lambda value: getattr(value, "flaw", "")
)
def test_every_card_stand_in_is_a_file_the_target_fingerprint_covers(
    card: CalibrationCard, target: CVETarget
):
    then.every_card_stand_in_is_fingerprinted(card, target)
