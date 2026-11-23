from typing import Literal

from evals.cve.census.census import Census
from evals.cve.census.work import AgentRole
from evals.cve.detection.draw_record import (
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
from tests.unit.support.census_draws import (
    A_DRAWN_FLAW,
    a_card,
    a_census_with_draw,
    a_draw,
    a_draw_carrying,
)


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


def a_draw_whose_card_has_a_stand_in_output_from(source: SourceKind) -> DrawRecord:
    output = StandInOutput(request="GET /api/status", source=source, citation="API reference")
    stand_in = StandInRecord(
        replaces="the vendor API",
        reason="the vendor API is a public host the closed network cannot reach",
        file="evals/docker/Dockerfile.vendor-responder",
        outputs=[output],
    )
    card_stand_in = CardStandIn(stand_in=stand_in, returned_by=["status"], used_by_default_by=[])
    return a_draw_carrying(a_card(A_DRAWN_FLAW).model_copy(update={"stand_ins": [card_stand_in]}))


def a_census_whose_drawn_flaw_calibrator_has(**update: object) -> Census:
    with_draw = a_census_with_draw(a_draw())
    agents = [
        agent.model_copy(update=update)
        if agent.scope == A_DRAWN_FLAW and agent.role == AgentRole.CALIBRATOR
        else agent
        for agent in with_draw.agents
    ]
    return with_draw.model_copy(update={"agents": agents})
