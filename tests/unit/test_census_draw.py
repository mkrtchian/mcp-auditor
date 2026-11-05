import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

import tests.unit.support.test_census_draw_given as given
import tests.unit.support.test_holdout_census_given as census
from evals.census_draw import CardStandIn, GiveUp, GiveUpReason, KeptPlace
from evals.census_work import AgentRole
from evals.fixture_provenance import SoftwareRelease, StandInOutput, StandInRecord
from evals.holdout_census import load_census
from evals.run_census import CENSUS_PATH
from tests.unit.support.test_census_draw_given import A_DRAWN_FLAW, A_TWICE_GIVEN_UP_FLAW


def test_a_well_formed_draw_loads(tmp_path: Path):
    with_draw = given.a_census_with_draw(given.a_draw())

    loaded = load_census(census.written(tmp_path, with_draw))

    assert loaded.draw == given.a_draw()


def test_the_committed_census_draw_validates_clean():
    # load_census runs draw_problems on a present draw and raises on any problem, so a clean load
    # with the draw present is the committed draw validating.
    assert load_census(CENSUS_PATH).draw is not None


def test_a_card_citing_an_unknown_place_id_fails(tmp_path: Path):
    card = given.a_card(A_DRAWN_FLAW).model_copy(
        update={"kept": [KeptPlace(place_id="no-such-place-xyz", reason="only the target")]}
    )
    draw = given.a_draw().model_copy(update={"cards": [card]})

    with pytest.raises(ValueError, match=re.escape("no-such-place-xyz")):
        load_census(census.written(tmp_path, given.a_census_with_draw(draw)))


def test_thirty_one_drawn_flaws_load(tmp_path: Path):
    identifiers = [f"CVE-2026-{i:04d}" for i in range(1, 32)]
    census_of_thirty_one = given.a_census_drawing(identifiers)

    loaded = load_census(census.written(tmp_path, census_of_thirty_one))

    assert loaded.draw == census_of_thirty_one.draw


def test_a_flaw_drawn_on_its_re_walk_after_two_earlier_give_ups_loads(tmp_path: Path):
    draw = given.a_draw_re_walking(A_TWICE_GIVEN_UP_FLAW, under=11)

    loaded = load_census(census.written(tmp_path, given.a_census_with_draw(draw)))

    assert loaded.draw == draw


def test_two_steps_of_one_flaw_under_one_version_fail(tmp_path: Path):
    draw = given.a_draw_re_walking(A_TWICE_GIVEN_UP_FLAW, under=None)

    refusal = f"walk lists flaw {A_TWICE_GIVEN_UP_FLAW} 2 times under rule version None"
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(census.written(tmp_path, given.a_census_with_draw(draw)))


def test_a_drawn_flaw_whose_governing_step_is_skipped_fails(tmp_path: Path):
    draw = given.a_draw_stepping_again(A_DRAWN_FLAW, outcome="skipped", under=11)

    refusal = f'drawn flaw {A_DRAWN_FLAW}: its governing walk step is "skipped", not "drawn"'
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(census.written(tmp_path, given.a_census_with_draw(draw)))


def test_two_give_ups_and_a_card_under_one_version_fail(tmp_path: Path):
    draw = given.a_draw_re_walking(A_TWICE_GIVEN_UP_FLAW, under=11)
    draw = given.with_give_ups_under(draw, A_TWICE_GIVEN_UP_FLAW, version=11)

    refusal = f"flaw {A_TWICE_GIVEN_UP_FLAW} has two give-ups and a card under rule version 11"
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(census.written(tmp_path, given.a_census_with_draw(draw)))


def test_thirty_drawn_flaws_disclosed_after_one_date_load(tmp_path: Path):
    identifiers = [f"CVE-2026-{i:04d}" for i in range(1, 31)]
    census_of_thirty = given.a_census_drawing(identifiers)

    loaded = load_census(census.written(tmp_path, census_of_thirty))

    assert loaded.draw == census_of_thirty.draw


def test_a_give_up_reason_outside_the_closed_set_fails_at_deserialization(tmp_path: Path):
    raw = json.loads(given.a_census_with_draw(given.a_draw()).model_dump_json())
    raw["draw"]["give_ups"][0]["reason"] = "banana"
    path = tmp_path / "holdout_census.json"
    path.write_text(json.dumps(raw))

    with pytest.raises(ValidationError, match="banana"):
        load_census(path)


def test_a_flaw_with_two_give_ups_and_a_card_fails(tmp_path: Path):
    cards = [given.a_card(A_DRAWN_FLAW), given.a_card(A_TWICE_GIVEN_UP_FLAW)]
    draw = given.a_draw().model_copy(update={"cards": cards})

    refusal = f"flaw {A_TWICE_GIVEN_UP_FLAW} has two give-ups and a card"
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(census.written(tmp_path, given.a_census_with_draw(draw)))


def test_a_second_calibration_give_up_with_no_first_fails(tmp_path: Path):
    orphan = GiveUp(
        flaw=A_DRAWN_FLAW,
        calibration=2,
        reason=GiveUpReason.EXPLOIT_CANNOT_REPRODUCE,
        detail="the exploit never reproduced",
        attempts=4,
    )
    draw = given.a_draw().model_copy(update={"give_ups": [orphan]})

    refusal = f"flaw {A_DRAWN_FLAW} has a second-calibration"
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(census.written(tmp_path, given.a_census_with_draw(draw)))


def test_a_drawn_flaw_with_no_card_check_fails(tmp_path: Path):
    draw = given.a_draw().model_copy(update={"card_checks": []})

    with pytest.raises(ValueError, match=re.escape(f"drawn flaw {A_DRAWN_FLAW} has no card check")):
        load_census(census.written(tmp_path, given.a_census_with_draw(draw)))


def test_a_card_flaw_with_no_calibrator_record_fails(tmp_path: Path):
    with_draw = given.a_census_with_draw(given.a_draw())
    agents = [agent for agent in with_draw.agents if agent.scope != A_DRAWN_FLAW]
    without_calibrator = with_draw.model_copy(update={"agents": agents})

    with pytest.raises(ValueError, match=re.escape(f"flaw {A_DRAWN_FLAW} has no calibrator")):
        load_census(census.written(tmp_path, without_calibrator))


def test_a_flaw_whose_only_calibrator_record_is_set_aside_has_no_calibrator(tmp_path: Path):
    with_draw = given.a_census_with_draw(given.a_draw())
    agents = [
        agent.model_copy(update={"set_aside": "a refusal on the fallback model"})
        if agent.scope == A_DRAWN_FLAW and agent.role == AgentRole.CALIBRATOR
        else agent
        for agent in with_draw.agents
    ]
    set_aside = with_draw.model_copy(update={"agents": agents})

    with pytest.raises(ValueError, match=re.escape(f"flaw {A_DRAWN_FLAW} has no calibrator")):
        load_census(census.written(tmp_path, set_aside))


def test_a_card_with_the_fields_rule_v9_adds_unset_loads(tmp_path: Path):
    card = given.a_card(A_DRAWN_FLAW)
    draw = given.a_draw().model_copy(update={"cards": [card]})

    loaded = load_census(census.written(tmp_path, given.a_census_with_draw(draw)))

    assert loaded.draw is not None
    assert loaded.draw.cards[0].stand_ins is None
    assert loaded.draw.cards[0].seeded_outside_layout is None


def test_a_card_stand_in_with_an_invented_output_and_no_form_source_fails(tmp_path: Path):
    output = StandInOutput(request="GET /api/status", source="invented", citation="none")
    stand_in = StandInRecord(
        replaces="the vendor API",
        reason="the vendor API is a public host the closed network cannot reach",
        file="evals/docker/Dockerfile.vendor-responder",
        outputs=[output],
    )
    card_stand_in = CardStandIn(stand_in=stand_in, returned_by=["status"], used_by_default_by=[])
    card = given.a_card(A_DRAWN_FLAW).model_copy(update={"stand_ins": [card_stand_in]})
    draw = given.a_draw().model_copy(update={"cards": [card]})

    refusal = f"card for flaw {A_DRAWN_FLAW}: stand-in for the vendor API"
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(census.written(tmp_path, given.a_census_with_draw(draw)))


def test_a_software_release_with_a_blank_source_fails(tmp_path: Path):
    release = SoftwareRelease(software="Neo4j", release="5.26.0", day=None, source=" ")
    draw = given.a_draw_whose_card_records(release)

    refusal = f"card for flaw {A_DRAWN_FLAW}: software release of Neo4j records no source"
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(census.written(tmp_path, given.a_census_with_draw(draw)))


def test_a_software_release_with_no_day_loads(tmp_path: Path):
    release = SoftwareRelease(
        software="Neo4j",
        release="5.26.0",
        day=None,
        source="the README: requires Neo4j 5.26",
    )
    draw = given.a_draw_whose_card_records(release)

    loaded = load_census(census.written(tmp_path, given.a_census_with_draw(draw)))

    assert loaded.draw == draw
