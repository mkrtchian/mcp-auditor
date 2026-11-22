import hashlib

import tests.unit.support.fictional_planting as planting
from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.cve.places import DETECTION_PLACES, REACHES, PlaceKind, kept_records, load_places
from evals.cve.planting import planting_spec

RECORDED_HASH = "240a7b83a977d0aca9e05952132d1d49acb581631360aee6793043fbff664f4b"


def test_the_imported_places_file_matches_the_recorded_hash():
    digest = hashlib.sha256(DETECTION_PLACES.read_bytes()).hexdigest()

    assert digest == RECORDED_HASH


def test_every_target_reaches_only_the_closed_vocabulary():
    for target in ACCEPTANCE_TARGETS:
        assert target.reaches <= REACHES, (
            f"{target.flaw_id}: reaches holds a token outside the closed vocabulary"
        )


def test_every_kept_place_is_offered_by_the_file_within_its_target_reach():
    places = load_places(DETECTION_PLACES)
    for target in ACCEPTANCE_TARGETS:
        for place_id in target.kept_places:
            assert place_id in places, f"{target.flaw_id}: keeps {place_id}, absent from the file"
            assert places[place_id].reaches & target.reaches, (
                f"{target.flaw_id}: keeps {place_id}, reachable by none of its reach"
            )


def test_no_target_keeps_an_unplaceable_place():
    places = load_places(DETECTION_PLACES)
    for target in ACCEPTANCE_TARGETS:
        for record in kept_records(target.kept_places, places):
            assert record.kind is not PlaceKind.UNPLACEABLE, (
                f"{target.flaw_id}: keeps {record.id}, an unplaceable place that plants nothing"
            )


def test_every_target_kept_list_plants_together():
    places = load_places(DETECTION_PLACES)
    for target in ACCEPTANCE_TARGETS:
        planting_spec(
            kept_records(target.kept_places, places),
            target.planting_host,
            planting.FakeNonces(),
        )
