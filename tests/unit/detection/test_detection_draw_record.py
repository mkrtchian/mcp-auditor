import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

import tests.unit.detection.support.test_detection_draw_record_given as given
from evals.cve.census.census import load_census
from evals.cve.census.classification import Criterion
from evals.cve.detection.draw_record import GiveUp, GiveUpReason, KeptPlace, Settlement
from evals.cve.fixture_provenance import SoftwareRelease
from tests.unit.support import census_draws, censuses
from tests.unit.support.census_draws import (
    A_DRAWN_FLAW,
    A_TWICE_GIVEN_UP_FLAW,
)


def test_a_well_formed_draw_loads(tmp_path: Path):
    with_draw = census_draws.a_census_with_draw(census_draws.a_draw())

    loaded = load_census(censuses.written(tmp_path, with_draw))

    assert loaded.draw == census_draws.a_draw()


def test_a_settlement_is_written_and_read_back_under_its_committed_key():
    settlement = Settlement(
        flaw=A_DRAWN_FLAW, criterion=Criterion.PINNABLE, ruling=True, reason="the maintainer"
    )

    written = settlement.model_dump_json()

    assert json.loads(written)["verdict"] is True
    assert "ruling" not in json.loads(written)
    assert Settlement.model_validate_json(written) == settlement


def test_a_card_citing_an_unknown_place_id_fails(tmp_path: Path):
    card = census_draws.a_card(A_DRAWN_FLAW).model_copy(
        update={"kept": [KeptPlace(place_id="no-such-place-xyz", reason="only the target")]}
    )
    draw = census_draws.a_draw_carrying(card)

    with pytest.raises(ValueError, match=re.escape("no-such-place-xyz")):
        load_census(censuses.written(tmp_path, census_draws.a_census_with_draw(draw)))


def test_thirty_one_drawn_flaws_load(tmp_path: Path):
    identifiers = [f"CVE-2026-{i:04d}" for i in range(1, 32)]
    census_of_thirty_one = census_draws.a_census_drawing(identifiers)

    loaded = load_census(censuses.written(tmp_path, census_of_thirty_one))

    assert loaded.draw == census_of_thirty_one.draw


def test_a_flaw_drawn_on_its_re_walk_after_two_earlier_give_ups_loads(tmp_path: Path):
    draw = given.a_draw_re_walking(A_TWICE_GIVEN_UP_FLAW, under=11)

    loaded = load_census(censuses.written(tmp_path, census_draws.a_census_with_draw(draw)))

    assert loaded.draw == draw


def test_two_steps_of_one_flaw_under_one_version_fail(tmp_path: Path):
    draw = given.a_draw_re_walking(A_TWICE_GIVEN_UP_FLAW, under=None)

    refusal = f"walk lists flaw {A_TWICE_GIVEN_UP_FLAW} 2 times before the first re-walk"
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(censuses.written(tmp_path, census_draws.a_census_with_draw(draw)))


def test_a_drawn_flaw_whose_governing_step_is_skipped_fails(tmp_path: Path):
    draw = given.a_draw_stepping_again(A_DRAWN_FLAW, outcome="skipped", under=11)

    refusal = f'drawn flaw {A_DRAWN_FLAW}: its governing walk step is "skipped", not "drawn"'
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(censuses.written(tmp_path, census_draws.a_census_with_draw(draw)))


def test_two_give_ups_and_a_card_under_one_version_fail(tmp_path: Path):
    draw = given.a_draw_re_walking(A_TWICE_GIVEN_UP_FLAW, under=11)
    draw = given.with_give_ups_under(draw, A_TWICE_GIVEN_UP_FLAW, version=11)

    refusal = (
        f"flaw {A_TWICE_GIVEN_UP_FLAW} has two give-ups and a card under detection suite rule v11"
    )
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(censuses.written(tmp_path, census_draws.a_census_with_draw(draw)))


def test_give_ups_under_a_version_with_no_walk_step_of_their_flaw_fail(tmp_path: Path):
    draw = given.with_give_ups_under(census_draws.a_draw(), A_TWICE_GIVEN_UP_FLAW, version=10)

    refusal = (
        f"flaw {A_TWICE_GIVEN_UP_FLAW} gave up under detection suite rule v10,"
        " which has no walk step"
    )
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(censuses.written(tmp_path, census_draws.a_census_with_draw(draw)))


def test_a_give_up_reason_outside_the_closed_set_fails_at_deserialization(tmp_path: Path):
    raw = json.loads(census_draws.a_census_with_draw(census_draws.a_draw()).model_dump_json())
    raw["draw"]["give_ups"][0]["reason"] = "banana"
    path = tmp_path / "census.json"
    path.write_text(json.dumps(raw))

    with pytest.raises(ValidationError, match="banana"):
        load_census(path)


def test_a_flaw_with_two_give_ups_and_a_card_fails(tmp_path: Path):
    draw = census_draws.a_draw_carrying(
        census_draws.a_card(A_DRAWN_FLAW), census_draws.a_card(A_TWICE_GIVEN_UP_FLAW)
    )

    refusal = f"flaw {A_TWICE_GIVEN_UP_FLAW} has two give-ups and a card"
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(censuses.written(tmp_path, census_draws.a_census_with_draw(draw)))


def test_a_second_calibration_give_up_with_no_first_fails(tmp_path: Path):
    orphan = GiveUp(
        flaw=A_DRAWN_FLAW,
        calibration=2,
        reason=GiveUpReason.EXPLOIT_CANNOT_REPRODUCE,
        detail="the exploit never reproduced",
        attempts=4,
    )
    draw = census_draws.a_draw().model_copy(update={"give_ups": [orphan]})

    refusal = f"flaw {A_DRAWN_FLAW} has a second-calibration"
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(censuses.written(tmp_path, census_draws.a_census_with_draw(draw)))


def test_a_drawn_flaw_with_no_card_check_fails(tmp_path: Path):
    draw = census_draws.a_draw().model_copy(update={"card_checks": []})

    with pytest.raises(ValueError, match=re.escape(f"drawn flaw {A_DRAWN_FLAW} has no card check")):
        load_census(censuses.written(tmp_path, census_draws.a_census_with_draw(draw)))


def test_a_card_flaw_with_no_calibrator_record_fails(tmp_path: Path):
    with_draw = census_draws.a_census_with_draw(census_draws.a_draw())
    agents = [agent for agent in with_draw.agents if agent.scope != A_DRAWN_FLAW]
    without_calibrator = with_draw.model_copy(update={"agents": agents})

    with pytest.raises(ValueError, match=re.escape(f"flaw {A_DRAWN_FLAW} has no calibrator")):
        load_census(censuses.written(tmp_path, without_calibrator))


def test_a_flaw_whose_only_calibrator_record_is_set_aside_has_no_calibrator(tmp_path: Path):
    set_aside = given.a_census_whose_drawn_flaw_calibrator_has(
        set_aside="a refusal on the fallback model"
    )

    with pytest.raises(ValueError, match=re.escape(f"flaw {A_DRAWN_FLAW} has no calibrator")):
        load_census(censuses.written(tmp_path, set_aside))


def test_a_census_whose_drawn_flaw_only_calibrator_carries_a_fallback_model_loads(
    tmp_path: Path,
):
    fell_back = given.a_census_whose_drawn_flaw_calibrator_has(
        model="claude-opus-5-5", fallback_model="claude-opus-4-8"
    )

    load_census(censuses.written(tmp_path, fell_back))


def test_a_card_stand_in_with_an_invented_output_and_no_form_source_fails(tmp_path: Path):
    draw = given.a_draw_whose_card_has_a_stand_in_output_from(source="invented")

    refusal = f"card for flaw {A_DRAWN_FLAW}: stand-in for the vendor API"
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(censuses.written(tmp_path, census_draws.a_census_with_draw(draw)))


def test_a_software_release_with_a_blank_source_fails(tmp_path: Path):
    release = SoftwareRelease(software="Neo4j", release="5.26.0", day=None, source=" ")
    draw = given.a_draw_whose_card_records(release)

    refusal = f"card for flaw {A_DRAWN_FLAW}: software release of Neo4j records no source"
    with pytest.raises(ValueError, match=re.escape(refusal)):
        load_census(censuses.written(tmp_path, census_draws.a_census_with_draw(draw)))


def test_a_software_release_with_no_day_loads(tmp_path: Path):
    release = SoftwareRelease(
        software="Neo4j",
        release="5.26.0",
        day=None,
        source="the README: requires Neo4j 5.26",
    )
    draw = given.a_draw_whose_card_records(release)

    loaded = load_census(censuses.written(tmp_path, census_draws.a_census_with_draw(draw)))

    assert loaded.draw == draw
