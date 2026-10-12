import hashlib
from pathlib import Path
from typing import Any

import pytest

import tests.unit.support.test_cve_places_given as given
from evals.cve_places import (
    HOLDOUT_PLACES,
    REACHABLE_BY,
    Place,
    PlantKind,
    is_endpoint_host,
    load_places,
)

RECORDED_HASH = "2e3b5263207c62af01c15c9b52fecc4857787e4048887cea178e9d17fd0e9ee3"


def test_the_imported_places_file_matches_the_recorded_hash():
    digest = hashlib.sha256(HOLDOUT_PLACES.read_bytes()).hexdigest()

    assert digest == RECORDED_HASH


def test_the_real_places_file_validates_under_its_schema():
    places = load_places(HOLDOUT_PLACES)

    assert len(places) == 33
    assert len({place.id for place in places.values()}) == 33
    for place in places.values():
        assert place.reachable_by <= REACHABLE_BY, (
            f"{place.id}: reachable_by holds a token outside the closed vocabulary"
        )
        _assert_coordinate_is_well_formed(place)


def _assert_coordinate_is_well_formed(place: Place) -> None:
    coordinates = place.coordinates
    if place.kind is PlantKind.FILE:
        raw_paths = coordinates.paths if coordinates.paths is not None else (coordinates.path,)
        for raw in raw_paths:
            assert raw is not None and given.resolve_file_path(raw).startswith("/"), (
                f"{place.id}: a file coordinate is not absolute once resolved"
            )
    elif place.kind is PlantKind.HTTP_ENDPOINT:
        assert coordinates.host is not None and is_endpoint_host(coordinates.host), (
            f"{place.id}: http_endpoint host is not a DNS name or an IPv4 literal"
        )
        assert coordinates.path is not None and coordinates.path.startswith("/"), (
            f"{place.id}: http_endpoint path is not absolute"
        )


def test_a_file_place_keeps_its_path(tmp_path: Path):
    [place] = given.loaded(
        tmp_path, [given.an_entry(kind="file", coordinates={"path": "/fictional/config"})]
    ).values()

    assert place.kind is PlantKind.FILE
    assert place.coordinates.path == "/fictional/config"


def test_a_file_place_keeps_its_paths(tmp_path: Path):
    coordinates = {"paths": ["/fictional/a", "~/b", "work/c"]}

    places = given.loaded(tmp_path, [given.an_entry(kind="file", coordinates=coordinates)])
    [place] = places.values()

    assert place.coordinates.paths == ("/fictional/a", "~/b", "work/c")


def test_reachable_by_round_trips(tmp_path: Path):
    [place] = given.loaded(
        tmp_path, [given.an_entry(reachable_by=["arbitrary_read", "internal_fetch"])]
    ).values()

    assert place.reachable_by == frozenset({"arbitrary_read", "internal_fetch"})


@pytest.mark.parametrize("kind", ["account", "hostname", "unplaceable"])
def test_an_empty_coordinate_kind_loads(tmp_path: Path, kind: str):
    [place] = given.loaded(tmp_path, [given.an_entry(kind=kind, coordinates={})]).values()

    assert place.kind is PlantKind(kind)


@pytest.mark.parametrize(
    ("kind", "coordinates"),
    [
        ("file", {"path": "/fictional/config"}),
        ("file", {"path": "~/fictional-secret"}),
        ("file", {"path": "$HOME/fictional-secret"}),
        ("file", {"path": "data/fictional"}),
        ("file", {"path": "/fictional/<account>/config"}),
        ("http_endpoint", {"host": "fictional.internal", "path": "/latest"}),
        ("http_endpoint", {"host": "192.0.2.10", "path": "/latest/meta"}),
    ],
    ids=[
        "absolute",
        "home_tilde",
        "home_variable",
        "relative",
        "one_placeholder",
        "dns_host",
        "ipv4_host",
    ],
)
def test_an_accepted_coordinate_notation_loads(
    tmp_path: Path, kind: str, coordinates: dict[str, Any]
):
    places = given.loaded(tmp_path, [given.an_entry(kind=kind, coordinates=coordinates)])

    assert "place-1" in places


@pytest.mark.parametrize(
    ("kind", "coordinates"),
    [
        ("file", {}),
        ("file", {"path": "/fictional/*.log"}),
        ("file", {"path": "/fictional/<a>/<b>/x"}),
        ("file", {"path": "/fictional/config", "mode": "0644"}),
        ("env", {}),
        ("http_endpoint", {"path": "/latest"}),
        ("http_endpoint", {"host": "fictional.internal"}),
        ("http_endpoint", {"host": "fictional.internal:80", "path": "/latest"}),
        ("http_endpoint", {"host": "http://fictional.internal", "path": "/latest"}),
        ("http_endpoint", {"host": "2001:db8::1", "path": "/latest"}),
        ("http_endpoint", {"host": "fictional.internal", "path": "relative"}),
        ("account", {"name": "fictional"}),
    ],
    ids=[
        "file_without_path_or_paths",
        "file_glob",
        "file_two_placeholders",
        "file_extra_key",
        "env_without_name",
        "endpoint_without_host",
        "endpoint_without_path",
        "endpoint_host_port",
        "endpoint_host_scheme",
        "endpoint_host_ipv6",
        "endpoint_relative_path",
        "empty_kind_with_coordinates",
    ],
)
def test_a_rejected_coordinate_raises_naming_the_entry(
    tmp_path: Path, kind: str, coordinates: dict[str, Any]
):
    with pytest.raises(ValueError, match="place-1"):
        given.loaded(tmp_path, [given.an_entry(kind=kind, coordinates=coordinates)])


def test_an_unknown_reachable_by_token_raises(tmp_path: Path):
    with pytest.raises(ValueError, match=r"place-1.*reachable_by"):
        given.loaded(tmp_path, [given.an_entry(reachable_by=["arbitrary_read", "mystery_token"])])


@pytest.mark.parametrize("missing", ["category", "technique_ids", "place"])
def test_an_entry_missing_a_required_top_level_field_raises(tmp_path: Path, missing: str):
    entry = given.an_entry()
    del entry[missing]

    with pytest.raises(ValueError, match=rf"place-1.*{missing}"):
        given.loaded(tmp_path, [entry])


def test_an_entry_with_an_extra_top_level_field_raises(tmp_path: Path):
    entry = given.an_entry()
    entry["surprise"] = "x"

    with pytest.raises(ValueError, match=r"place-1.*surprise"):
        given.loaded(tmp_path, [entry])


def test_duplicate_ids_raise(tmp_path: Path):
    with pytest.raises(ValueError, match="dup"):
        given.loaded(tmp_path, [given.an_entry("dup"), given.an_entry("dup")])
