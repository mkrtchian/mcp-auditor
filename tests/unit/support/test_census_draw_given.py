from datetime import date

import tests.unit.support.test_census_figures_given as figures
import tests.unit.support.test_holdout_census_given as census_given
from evals.census_draw import (
    CalibrationCard,
    CardCheck,
    DrawRecord,
    DrawWalkStep,
    GiveUp,
    GiveUpReason,
)
from evals.census_figures import compute_figures
from evals.census_grouping import READERS, ProofJudgment, gap_population, known_gap
from evals.census_sources import SourceName, SourceRecord
from evals.census_work import AgentRecord, AgentRole
from evals.holdout_census import CLASSIFIERS, CensusFlaw, Discovery, HoldoutCensus, draw_candidates

A_DRAWN_FLAW = "CVE-2025-0001"
A_TWICE_GIVEN_UP_FLAW = "GHSA-dddd-eeee-ffff"


def a_draw() -> DrawRecord:
    return DrawRecord(
        rule_commit="abc1234",
        grammar_fingerprint="deadbeef",
        settlements=[],
        walk=[
            DrawWalkStep(identifier=A_DRAWN_FLAW, outcome="drawn", reason=""),
            DrawWalkStep(
                identifier=A_TWICE_GIVEN_UP_FLAW,
                outcome="given_up",
                reason="no place reached on either calibration",
            ),
        ],
        cards=[a_card(A_DRAWN_FLAW)],
        card_checks=[CardCheck(flaw=A_DRAWN_FLAW, reported_gaps=[], confirmed_gaps=[])],
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
        fallback_scope=None,
        fallback_documentation=None,
        exploit_calls=["read_file"],
        benign_call="read_file",
        patched_result="the patched server refuses the traversal",
        attempts=3,
    )


def a_census_with_draw(draw: DrawRecord) -> HoldoutCensus:
    census = census_given.a_census()
    model = "claude-opus-4-8"
    agents = [
        *census.agents,
        AgentRecord(role=AgentRole.CALIBRATOR, scope=A_DRAWN_FLAW, model=model),
        AgentRecord(role=AgentRole.CALIBRATOR, scope=A_TWICE_GIVEN_UP_FLAW, model=model),
        AgentRecord(role=AgentRole.CARD_CHECKER, scope=A_DRAWN_FLAW, model=model),
    ]
    return census.model_copy(update={"agents": agents, "draw": draw})


def a_census_drawing(identifiers: list[str]) -> HoldoutCensus:
    flaws = [_flaw(identifier) for identifier in identifiers]
    classifications = {
        classifier: [figures.a_classification(flaw=identifier) for identifier in identifiers]
        for classifier in CLASSIFIERS
    }
    dates = {identifier: date(2025, 6, 10) for identifier in identifiers}
    groupings: dict[str, list[ProofJudgment]] = {reader: [] for reader in READERS}
    population = gap_population(classifications, draw_candidates(flaws))
    calibration = [
        AgentRecord(role=role, scope=identifier, model="m")
        for identifier in identifiers
        for role in (AgentRole.CALIBRATOR, AgentRole.CARD_CHECKER)
    ]
    return HoldoutCensus(
        sources=census_given.a_provenance(),
        agents=[
            *(AgentRecord(role=AgentRole.READER, scope=reader, model="m") for reader in READERS),
            *calibration,
        ],
        prefilter=[],
        hits=[],
        flaws=flaws,
        vulnerablemcp=[],
        classifications=classifications,
        date_mismatches=[],
        figures=compute_figures(classifications, dates, set()),
        groupings=groupings,
        known_gap=known_gap(groupings, population),
        draw=_a_draw_of(identifiers),
    )


def _flaw(identifier: str) -> CensusFlaw:
    record = SourceRecord(
        source=SourceName.NVD,
        id=identifier,
        published=date(2025, 6, 10),
        withdrawn=None,
        rejected=False,
    )
    return CensusFlaw(
        identifier=identifier,
        no_census_identifier=False,
        ids=[identifier],
        records=[record],
        disclosure_date=date(2025, 6, 10),
        found_by=[Discovery.PREFILTER],
    )


def _a_draw_of(identifiers: list[str]) -> DrawRecord:
    return DrawRecord(
        rule_commit="abc1234",
        grammar_fingerprint="deadbeef",
        settlements=[],
        walk=[
            DrawWalkStep(identifier=identifier, outcome="drawn", reason="")
            for identifier in identifiers
        ],
        cards=[a_card(identifier) for identifier in identifiers],
        card_checks=[
            CardCheck(flaw=identifier, reported_gaps=[], confirmed_gaps=[])
            for identifier in identifiers
        ],
        give_ups=[],
        drawn=identifiers,
    )
