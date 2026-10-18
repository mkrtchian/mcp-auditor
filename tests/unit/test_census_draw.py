import json
import re
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

import tests.unit.support.test_census_figures_given as figures
import tests.unit.support.test_holdout_census_given as given
from evals.census_draw import (
    CalibrationCard,
    CardCheck,
    DrawRecord,
    DrawWalkStep,
    GiveUp,
    GiveUpReason,
    KeptPlace,
    draw_problems,
)
from evals.census_figures import compute_figures
from evals.census_grouping import (
    READERS,
    ProofJudgment,
    draw_order_flaws,
    gap_population,
    known_gap,
)
from evals.census_sources import SourceFile, SourceName, SourceProvenance, SourceRecord
from evals.census_work import AgentRecord, AgentRole
from evals.holdout_census import (
    CLASSIFIERS,
    CensusFlaw,
    Discovery,
    HoldoutCensus,
    draw_candidates,
    load_census,
)
from evals.run_census import CENSUS_PATH

A_DRAWN_FLAW = "CVE-2025-0001"
A_TWICE_GIVEN_UP_FLAW = "GHSA-dddd-eeee-ffff"


def test_a_well_formed_draw_loads(tmp_path: Path):
    census = _census_with_draw(_a_draw())

    loaded = load_census(given.written(tmp_path, census))

    assert loaded.draw == _a_draw()


def test_the_committed_census_has_no_draw():
    assert load_census(CENSUS_PATH).draw is None


def test_a_card_citing_an_unknown_place_id_fails(tmp_path: Path):
    card = _a_card(A_DRAWN_FLAW).model_copy(
        update={"kept": [KeptPlace(place_id="no-such-place-xyz", reason="only the target")]}
    )
    draw = _a_draw().model_copy(update={"cards": [card]})

    with pytest.raises(ValueError, match=re.escape("no-such-place-xyz")):
        load_census(given.written(tmp_path, _census_with_draw(draw)))


def test_a_drawn_list_over_twenty_fails(tmp_path: Path):
    draw = _a_draw().model_copy(update={"drawn": [f"CVE-2027-{i:04d}" for i in range(21)]})

    with pytest.raises(ValueError, match="more than 20"):
        load_census(given.written(tmp_path, _census_with_draw(draw)))


def test_twenty_drawn_flaws_disclosed_after_one_date_raise_no_problem():
    identifiers = [f"CVE-2026-{i:04d}" for i in range(1, 21)]
    census = _census_of(identifiers, _a_draw_of(identifiers))
    assert census.draw is not None

    problems = draw_problems(
        census.draw,
        set(draw_order_flaws(census.classifications, draw_candidates(census.flaws))),
        {flaw.identifier: flaw.disclosure_date for flaw in census.flaws},
        set(),
        census.agents,
    )

    assert problems == []


def test_a_give_up_reason_outside_the_closed_set_fails_at_deserialization(tmp_path: Path):
    census = _census_with_draw(_a_draw())
    raw = json.loads(census.model_dump_json())
    raw["draw"]["give_ups"][0]["reason"] = "banana"
    path = tmp_path / "holdout_census.json"
    path.write_text(json.dumps(raw))

    with pytest.raises(ValidationError, match="banana"):
        load_census(path)


def test_a_flaw_with_two_give_ups_and_a_card_fails(tmp_path: Path):
    cards = [_a_card(A_DRAWN_FLAW), _a_card(A_TWICE_GIVEN_UP_FLAW)]
    draw = _a_draw().model_copy(update={"cards": cards})

    refusal = f"flaw {A_TWICE_GIVEN_UP_FLAW} has two give-ups"
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(given.written(tmp_path, _census_with_draw(draw)))


def test_a_second_calibration_give_up_with_no_first_fails(tmp_path: Path):
    orphan = GiveUp(
        flaw=A_DRAWN_FLAW,
        calibration=2,
        reason=GiveUpReason.EXPLOIT_CANNOT_REPRODUCE,
        detail="the exploit never reproduced",
        attempts=4,
    )
    draw = _a_draw().model_copy(update={"give_ups": [orphan]})

    refusal = f"flaw {A_DRAWN_FLAW} has a second-calibration"
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(given.written(tmp_path, _census_with_draw(draw)))


def test_a_drawn_flaw_with_no_card_check_fails(tmp_path: Path):
    draw = _a_draw().model_copy(update={"card_checks": []})

    with pytest.raises(ValueError, match=re.escape(f"drawn flaw {A_DRAWN_FLAW} has no card check")):
        load_census(given.written(tmp_path, _census_with_draw(draw)))


def test_a_card_flaw_with_no_calibrator_record_fails(tmp_path: Path):
    census = _census_with_draw(_a_draw())
    agents = [agent for agent in census.agents if agent.scope != A_DRAWN_FLAW]
    census = census.model_copy(update={"agents": agents})

    with pytest.raises(ValueError, match=re.escape(f"flaw {A_DRAWN_FLAW} has no calibrator")):
        load_census(given.written(tmp_path, census))


def _a_draw() -> DrawRecord:
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
        cards=[_a_card(A_DRAWN_FLAW)],
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


def _a_draw_of(identifiers: list[str]) -> DrawRecord:
    return DrawRecord(
        rule_commit="abc1234",
        grammar_fingerprint="deadbeef",
        settlements=[],
        walk=[
            DrawWalkStep(identifier=identifier, outcome="drawn", reason="")
            for identifier in identifiers
        ],
        cards=[_a_card(identifier) for identifier in identifiers],
        card_checks=[
            CardCheck(flaw=identifier, reported_gaps=[], confirmed_gaps=[])
            for identifier in identifiers
        ],
        give_ups=[],
        drawn=identifiers,
    )


def _a_card(flaw: str) -> CalibrationCard:
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


def _census_with_draw(draw: DrawRecord) -> HoldoutCensus:
    census = given.a_census()
    model = "claude-opus-4-8"
    agents = [
        *census.agents,
        AgentRecord(role=AgentRole.CALIBRATOR, scope=A_DRAWN_FLAW, model=model),
        AgentRecord(role=AgentRole.CALIBRATOR, scope=A_TWICE_GIVEN_UP_FLAW, model=model),
        AgentRecord(role=AgentRole.CARD_CHECKER, scope=A_DRAWN_FLAW, model=model),
    ]
    return census.model_copy(update={"agents": agents, "draw": draw})


def _census_of(identifiers: list[str], draw: DrawRecord) -> HoldoutCensus:
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
        sources=_provenance(),
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
        draw=draw,
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


def _provenance() -> SourceProvenance:
    a_file = SourceFile(name="all.zip", downloaded=date(2026, 10, 8), sha256="0" * 64)
    return SourceProvenance(
        ghsa_commit="1" * 40,
        nvd_feeds=[a_file.model_copy(update={"name": "nvdcve-2.0-2025.json.gz"})],
        osv_export=a_file,
    )
