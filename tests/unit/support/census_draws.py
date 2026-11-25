from datetime import date

from evals.cve.census.census import CLASSIFIERS, Census, derived_parts
from evals.cve.census.grouping import READERS, ProofJudgment
from evals.cve.census.work import AgentRecord, AgentRole
from evals.cve.detection.draw_record import (
    CalibrationCard,
    CardCheck,
    DetectionWalkStep,
    DrawRecord,
    GiveUp,
    GiveUpReason,
)
from tests.unit.support import advisory_sources, censuses

A_DRAWN_FLAW = "CVE-2025-0001"
A_TWICE_GIVEN_UP_FLAW = "GHSA-dddd-eeee-ffff"


def a_draw_carrying(*cards: CalibrationCard) -> DrawRecord:
    return a_draw().model_copy(update={"cards": list(cards)})


def a_draw() -> DrawRecord:
    return DrawRecord(
        rule_commit="abc1234",
        grammar_fingerprint="deadbeef",
        settlements=[],
        walk=[
            DetectionWalkStep(identifier=A_DRAWN_FLAW, outcome="drawn", reason=""),
            DetectionWalkStep(
                identifier=A_TWICE_GIVEN_UP_FLAW,
                outcome="given_up",
                reason="no place reached on either calibration",
            ),
        ],
        cards=[a_card(A_DRAWN_FLAW)],
        card_checks=[
            CardCheck(flaw=A_DRAWN_FLAW, reported_gaps=[], confirmed_gaps=[], rule_version=11)
        ],
        give_ups=[
            GiveUp(
                flaw=A_DRAWN_FLAW,
                calibration=1,
                reason=GiveUpReason.NO_PLACE_REACHED,
                detail="the first fixture reached no place",
                attempts=2,
            ),
            GiveUp(
                flaw=A_TWICE_GIVEN_UP_FLAW,
                calibration=1,
                reason=GiveUpReason.NO_PLACE_REACHED,
                detail="no place reached",
                attempts=3,
            ),
            GiveUp(
                flaw=A_TWICE_GIVEN_UP_FLAW,
                calibration=2,
                reason=GiveUpReason.EXPLOIT_CANNOT_REPRODUCE,
                detail="the exploit never reproduced",
                attempts=4,
            ),
        ],
        drawn=[A_DRAWN_FLAW],
    )


def a_card(flaw: str) -> CalibrationCard:
    return CalibrationCard(
        flaw=flaw,
        mechanism="an arbitrary read through a path argument",
        effect_class="read_outside_scope",
        siblings=[],
        kept=[],
        unkept=[],
        launch_options=[],
        seeded_in_layout=[],
        seeded_outside_layout=[],
        stand_ins=[],
        software_releases=[],
        fallback_scope=None,
        fallback_documentation=None,
        exploit_calls=["read_file"],
        benign_call="read_file",
        patched_result="the patched server refuses the traversal",
        attempts=3,
    )


def a_census_with_draw(draw: DrawRecord) -> Census:
    census = censuses.a_census()
    model = "claude-opus-4-8"
    agents = [
        *census.agents,
        AgentRecord(role=AgentRole.CALIBRATOR, scope=A_DRAWN_FLAW, model=model),
        AgentRecord(role=AgentRole.CALIBRATOR, scope=A_TWICE_GIVEN_UP_FLAW, model=model),
        AgentRecord(role=AgentRole.CARD_CHECKER, scope=A_DRAWN_FLAW, model=model),
        AgentRecord(role=AgentRole.CARD_CHECKER, scope=A_TWICE_GIVEN_UP_FLAW, model=model),
    ]
    return census.model_copy(update={"agents": agents, "draw": draw})


def a_census_drawing(identifiers: list[str]) -> Census:
    flaws = [
        censuses.a_flaw_with_records(
            advisory_sources.an_nvd(identifier, published=date(2025, 6, 10))
        )
        for identifier in identifiers
    ]
    classifications = {
        classifier: [censuses.a_classification(flaw=identifier) for identifier in identifiers]
        for classifier in CLASSIFIERS
    }
    groupings: dict[str, list[ProofJudgment]] = {reader: [] for reader in READERS}
    derived = derived_parts(flaws, classifications, groupings)
    calibration = [
        AgentRecord(role=role, scope=identifier, model="m")
        for identifier in identifiers
        for role in (AgentRole.CALIBRATOR, AgentRole.CARD_CHECKER)
    ]
    return Census(
        sources=censuses.a_provenance(),
        agents=[
            *(AgentRecord(role=AgentRole.READER, scope=reader, model="m") for reader in READERS),
            *calibration,
        ],
        prefilter=[],
        hits=[],
        flaws=flaws,
        vulnerablemcp=[],
        classifications=classifications,
        date_mismatches=derived.date_mismatches,
        figures=derived.figures,
        groupings=groupings,
        known_gap=derived.known_gap,
        draw=_a_draw_of(identifiers),
    )


def _a_draw_of(identifiers: list[str]) -> DrawRecord:
    return DrawRecord(
        rule_commit="abc1234",
        grammar_fingerprint="deadbeef",
        settlements=[],
        walk=[
            DetectionWalkStep(identifier=identifier, outcome="drawn", reason="")
            for identifier in identifiers
        ],
        cards=[a_card(identifier) for identifier in identifiers],
        card_checks=[
            CardCheck(flaw=identifier, reported_gaps=[], confirmed_gaps=[], rule_version=11)
            for identifier in identifiers
        ],
        give_ups=[],
        drawn=identifiers,
    )


def with_a_walk_skipping(census: Census, flaw: str) -> Census:
    """The census with a draw whose detection walk is one `skipped` step on `flaw`, which
    `load_census` accepts with no card and no calibration agent."""
    skipped = DetectionWalkStep(identifier=flaw, outcome="skipped", reason="")
    return census.model_copy(update={"draw": a_cardless_draw([skipped])})


def a_cardless_draw(walk: list[DetectionWalkStep]) -> DrawRecord:
    return DrawRecord(
        rule_commit="abc1234",
        grammar_fingerprint="deadbeef",
        settlements=[],
        walk=walk,
        cards=[],
        card_checks=[],
        give_ups=[],
        drawn=[],
    )
