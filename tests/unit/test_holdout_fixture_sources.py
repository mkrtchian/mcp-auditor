import pytest

import tests.unit.support.test_holdout_fixture_sources_then as then
from evals.cve.census.census import load_census
from evals.holdout_targets import HOLDOUT_TARGETS
from evals.run_census import CENSUS_PATH


def test_every_committed_card_stand_in_is_a_file_the_target_fingerprint_covers():
    targets = {target.cve_id: target for target in HOLDOUT_TARGETS}
    draw = load_census(CENSUS_PATH).draw
    cards = [] if draw is None else draw.cards
    with_stand_ins = [card for card in cards if card.flaw in targets and card.stand_ins]
    if not with_stand_ins:
        pytest.skip("no committed card records a stand-in")

    for card in with_stand_ins:
        then.every_card_stand_in_is_fingerprinted(card, targets[card.flaw])
