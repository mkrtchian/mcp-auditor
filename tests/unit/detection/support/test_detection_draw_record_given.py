from collections.abc import Sequence
from typing import Literal

from evals.cve.detection.draw_record import (
    CalibrationCard,
    CardCheck,
    CardStandIn,
    DetectionWalkStep,
    DrawRecord,
)
from evals.cve.fixture_provenance import (
    SoftwareRelease,
    SourceKind,
    StandInOutput,
    StandInRecord,
)
from tests.unit.support.census_draws import A_DRAWN_FLAW, a_card, a_draw, a_draw_carrying


def a_draw_re_walking(flaw: str, under: int | None) -> DrawRecord:
    """`a_draw` with `flaw`, given up twice under no version, drawn again under `under`."""
    draw = a_draw_stepping_again(flaw, outcome="drawn", under=under)
    return draw.model_copy(
        update={
            "cards": [*draw.cards, a_card(flaw)],
            "card_checks": [
                *draw.card_checks,
                CardCheck(flaw=flaw, reported_gaps=[], confirmed_gaps=[], rule_version=11),
            ],
            "drawn": [*draw.drawn, flaw],
        }
    )


def a_draw_stepping_again(
    flaw: str, outcome: Literal["drawn", "skipped", "given_up", "excluded"], under: int | None
) -> DrawRecord:
    draw = a_draw()
    step = DetectionWalkStep(identifier=flaw, outcome=outcome, reason="", rule_version=under)
    return draw.model_copy(update={"walk": [*draw.walk, step]})


def with_give_ups_under(draw: DrawRecord, flaw: str, version: int) -> DrawRecord:
    give_ups = [
        give_up.model_copy(update={"rule_version": version}) if give_up.flaw == flaw else give_up
        for give_up in draw.give_ups
    ]
    return draw.model_copy(update={"give_ups": give_ups})


def a_draw_whose_card_records(release: SoftwareRelease) -> DrawRecord:
    return a_draw_carrying(a_card(A_DRAWN_FLAW).model_copy(update={"software_releases": [release]}))


def a_card_stand_in(
    file: str,
    request: str,
    *,
    source: SourceKind = "software_sources",
    replaces: str = "the vendor API",
    returned_by: Sequence[str] = (),
) -> CardStandIn:
    output = StandInOutput(request=request, source=source, citation="API reference")
    stand_in = StandInRecord(
        replaces=replaces,
        reason=f"{replaces} is a public host the closed network cannot reach",
        file=file,
        outputs=[output],
    )
    return CardStandIn(stand_in=stand_in, returned_by=list(returned_by), used_by_default_by=[])


def a_card_with_a_stand_in(flaw: str, stand_in: CardStandIn) -> CalibrationCard:
    return a_card(flaw).model_copy(update={"stand_ins": [stand_in]})
