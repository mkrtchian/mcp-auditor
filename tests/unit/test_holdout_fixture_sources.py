import pytest

import tests.unit.support.test_holdout_fixture_sources_then as then
from evals.census_draw import CalibrationCard, CardStandIn
from evals.cve_targets import CVETarget
from evals.fixture_provenance import StandInOutput, StandInRecord
from evals.holdout_census import load_census
from evals.holdout_targets import HOLDOUT_TARGETS
from evals.run_census import CENSUS_PATH
from tests.unit.support.test_census_draw_given import a_card

_TARGETS = {target.cve_id: target for target in HOLDOUT_TARGETS}
_DORIS = _TARGETS["CVE-2025-66335"]


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


def _a_card_with_a_stand_in(file: str, request: str) -> CalibrationCard:
    output = StandInOutput(request=request, source="software_sources", citation="Doris manual")
    stand_in = StandInRecord(replaces="Doris", reason="a cluster", file=file, outputs=[output])
    card_stand_in = CardStandIn(stand_in=stand_in, returned_by=[], used_by_default_by=[])
    return a_card(_DORIS.cve_id).model_copy(update={"stand_ins": [card_stand_in]})


def test_a_card_stand_in_in_a_backend_source_holding_its_request_passes():
    card = _a_card_with_a_stand_in("evals/doris_backend.py", "CREATE TABLE")

    then.every_card_stand_in_is_fingerprinted(card, _DORIS)


def test_a_card_stand_in_in_a_fixture_module_the_fingerprint_does_not_hash_is_refused():
    card = _a_card_with_a_stand_in("evals/holdout_fixtures/cve_2025_66335_doris.py", "UNION")

    with pytest.raises(AssertionError):
        then.every_card_stand_in_is_fingerprinted(card, _DORIS)
