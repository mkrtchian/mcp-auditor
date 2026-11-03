"""Whether each drawn target's calibration card is ready for a holdout run: the card carries the
fields holdout rule v9 adds, and its second-agent check ran under rule v9 or later."""

from collections.abc import Sequence

from evals.census_draw import CalibrationCard, CardCheck, DrawRecord

CARD_CHECK_RULE_VERSION = 9


def unready_cards(draw: DrawRecord | None, drawn: Sequence[str]) -> list[str]:
    if draw is None:
        return [f"{identifier}: no draw record" for identifier in drawn]
    cards = {card.flaw: card for card in draw.cards}
    checks = {check.flaw: check for check in draw.card_checks}
    gaps: list[str] = []
    for identifier in drawn:
        missing = [
            *_card_gaps(cards.get(identifier)),
            *_check_gaps(checks.get(identifier)),
        ]
        if missing:
            gaps.append(f"{identifier}: {', '.join(missing)}")
    return gaps


def _card_gaps(card: CalibrationCard | None) -> list[str]:
    if card is None:
        return ["no card"]
    unset = {
        "seeded_outside_layout": card.seeded_outside_layout,
        "stand_ins": card.stand_ins,
    }
    return [f"{field} unset" for field, value in unset.items() if value is None]


def _check_gaps(check: CardCheck | None) -> list[str]:
    if check is None:
        return ["no card check"]
    if check.rule_version is None:
        return ["card check rule version unset"]
    if check.rule_version < CARD_CHECK_RULE_VERSION:
        return [f"card check at rule version {check.rule_version}, below {CARD_CHECK_RULE_VERSION}"]
    return []
