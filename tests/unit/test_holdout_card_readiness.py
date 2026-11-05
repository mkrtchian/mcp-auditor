import pytest

import tests.unit.support.test_census_draw_given as given
from evals.census_draw import CalibrationCard, DrawRecord
from evals.holdout_card_readiness import unready_cards
from tests.unit.support.test_census_draw_given import A_DRAWN_FLAW


def _with_card(draw: DrawRecord, **update: object) -> DrawRecord:
    card: CalibrationCard = draw.cards[0].model_copy(update=update)
    return draw.model_copy(update={"cards": [card]})


def _with_check_version(draw: DrawRecord, version: int | None) -> DrawRecord:
    check = draw.card_checks[0].model_copy(update={"rule_version": version})
    return draw.model_copy(update={"card_checks": [check]})


def test_a_ready_card_and_check_give_no_gap():
    assert unready_cards(given.a_ready_draw(), [A_DRAWN_FLAW]) == []


def test_a_check_at_a_later_rule_version_passes():
    assert unready_cards(_with_check_version(given.a_ready_draw(), 12), [A_DRAWN_FLAW]) == []


@pytest.mark.parametrize(
    ("draw", "gap"),
    [
        (
            _with_card(given.a_ready_draw(), seeded_outside_layout=None),
            "seeded_outside_layout unset",
        ),
        (_with_card(given.a_ready_draw(), stand_ins=None), "stand_ins unset"),
        (_with_card(given.a_ready_draw(), software_releases=None), "software_releases unset"),
        (given.a_ready_draw().model_copy(update={"cards": []}), "no card"),
        (given.a_ready_draw().model_copy(update={"card_checks": []}), "no card check"),
        (_with_check_version(given.a_ready_draw(), None), "card check rule version unset"),
        (
            _with_check_version(given.a_ready_draw(), 10),
            "card check at rule version 10, below 11",
        ),
    ],
    ids=[
        "seeded outside layout unset",
        "stand-ins unset",
        "software releases unset",
        "no card",
        "no check",
        "check with no version",
        "check at version 10",
    ],
)
def test_each_gap_is_named_for_its_target(draw: DrawRecord, gap: str):
    assert unready_cards(draw, [A_DRAWN_FLAW]) == [f"{A_DRAWN_FLAW}: {gap}"]


def test_no_draw_names_every_drawn_target():
    assert unready_cards(None, [A_DRAWN_FLAW, "CVE-2025-0002"]) == [
        f"{A_DRAWN_FLAW}: no draw record",
        "CVE-2025-0002: no draw record",
    ]
