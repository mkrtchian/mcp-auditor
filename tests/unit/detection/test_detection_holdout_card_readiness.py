import pytest

from evals.cve.detection.draw_record import DrawRecord
from evals.cve.detection.holdout_card_readiness import unready_cards
from tests.unit.support import census_draws
from tests.unit.support.census_draws import A_DRAWN_FLAW


def _with_check_version(draw: DrawRecord, version: int) -> DrawRecord:
    check = draw.card_checks[0].model_copy(update={"rule_version": version})
    return draw.model_copy(update={"card_checks": [check]})


def test_a_ready_card_and_check_give_no_gap():
    assert unready_cards(census_draws.a_draw(), [A_DRAWN_FLAW]) == []


def test_a_check_at_a_later_rule_version_passes():
    assert unready_cards(_with_check_version(census_draws.a_draw(), 12), [A_DRAWN_FLAW]) == []


@pytest.mark.parametrize(
    ("draw", "gap"),
    [
        (census_draws.a_draw().model_copy(update={"cards": []}), "no card"),
        (census_draws.a_draw().model_copy(update={"card_checks": []}), "no card check"),
        (
            _with_check_version(census_draws.a_draw(), 10),
            "card check under detection suite rule v10, below v11",
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
