import pytest

import tests.unit.support.test_census_draw_given as given
from evals.census_draw import CalibrationCard, CardCheck, DrawRecord
from evals.holdout_card_readiness import unready_cards
from tests.unit.support.test_census_draw_given import A_DRAWN_FLAW


def _ready_draw() -> DrawRecord:
    card = given.a_card(A_DRAWN_FLAW).model_copy(
        update={"seeded_outside_layout": [], "stand_ins": []}
    )
    check = CardCheck(flaw=A_DRAWN_FLAW, reported_gaps=[], confirmed_gaps=[], rule_version=9)
    return given.a_draw().model_copy(update={"cards": [card], "card_checks": [check]})


def _with_card(draw: DrawRecord, **update: object) -> DrawRecord:
    card: CalibrationCard = draw.cards[0].model_copy(update=update)
    return draw.model_copy(update={"cards": [card]})


def _with_check_version(draw: DrawRecord, version: int | None) -> DrawRecord:
    check = draw.card_checks[0].model_copy(update={"rule_version": version})
    return draw.model_copy(update={"card_checks": [check]})


def test_a_ready_card_and_check_give_no_gap():
    assert unready_cards(_ready_draw(), [A_DRAWN_FLAW]) == []


def test_a_check_at_a_later_rule_version_passes():
    assert unready_cards(_with_check_version(_ready_draw(), 10), [A_DRAWN_FLAW]) == []


@pytest.mark.parametrize(
    ("draw", "named"),
    [
        (_with_card(_ready_draw(), seeded_outside_layout=None), "seeded_outside_layout"),
        (_with_card(_ready_draw(), stand_ins=None), "stand_ins"),
        (_ready_draw().model_copy(update={"cards": []}), "no card"),
        (_ready_draw().model_copy(update={"card_checks": []}), "no card check"),
        (_with_check_version(_ready_draw(), None), "rule version"),
        (_with_check_version(_ready_draw(), 8), "rule version 8"),
    ],
    ids=[
        "seeded outside layout unset",
        "stand-ins unset",
        "no card",
        "no check",
        "check with no version",
        "check at version 8",
    ],
)
def test_each_gap_is_named_for_its_target(draw: DrawRecord, named: str):
    gaps = unready_cards(draw, [A_DRAWN_FLAW])

    assert len(gaps) == 1
    assert A_DRAWN_FLAW in gaps[0]
    assert named in gaps[0]


def test_no_draw_names_every_drawn_target():
    gaps = unready_cards(None, [A_DRAWN_FLAW, "CVE-2025-0002"])

    assert [A_DRAWN_FLAW in gaps[0], "CVE-2025-0002" in gaps[1]] == [True, True]
