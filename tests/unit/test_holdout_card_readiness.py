import pytest
from pydantic import ValidationError

import tests.unit.support.test_census_draw_given as given
from evals.census_draw import CardCheck, DrawRecord
from evals.holdout_card_readiness import unready_cards
from tests.unit.support.test_census_draw_given import A_DRAWN_FLAW


def _with_check_version(draw: DrawRecord, version: int) -> DrawRecord:
    check = draw.card_checks[0].model_copy(update={"rule_version": version})
    return draw.model_copy(update={"card_checks": [check]})


def test_a_ready_card_and_check_give_no_gap():
    assert unready_cards(given.a_draw(), [A_DRAWN_FLAW]) == []


def test_a_check_at_a_later_rule_version_passes():
    assert unready_cards(_with_check_version(given.a_draw(), 12), [A_DRAWN_FLAW]) == []


def test_a_check_without_a_rule_version_does_not_load():
    with pytest.raises(ValidationError, match="rule_version"):
        CardCheck.model_validate({"flaw": A_DRAWN_FLAW, "reported_gaps": [], "confirmed_gaps": []})


@pytest.mark.parametrize(
    ("draw", "gap"),
    [
        (given.a_draw().model_copy(update={"cards": []}), "no card"),
        (given.a_draw().model_copy(update={"card_checks": []}), "no card check"),
        (
            _with_check_version(given.a_draw(), 10),
            "card check at rule version 10, below 11",
        ),
    ],
    ids=["no card", "no check", "check at version 10"],
)
def test_each_gap_is_named_for_its_target(draw: DrawRecord, gap: str):
    assert unready_cards(draw, [A_DRAWN_FLAW]) == [f"{A_DRAWN_FLAW}: {gap}"]


def test_no_draw_names_every_drawn_target():
    assert unready_cards(None, [A_DRAWN_FLAW, "CVE-2025-0002"]) == [
        f"{A_DRAWN_FLAW}: no draw record",
        "CVE-2025-0002: no draw record",
    ]
