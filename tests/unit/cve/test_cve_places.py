from pathlib import Path
from typing import Any

import pytest

import tests.unit.cve.support.test_cve_places_given as given
from evals.cve.places import LayoutAnchor, PlaceKind


def test_a_file_place_keeps_its_path(tmp_path: Path):
    [place] = given.loaded(
        tmp_path, [given.an_entry(kind="file", coordinates={"path": "/fictional/config"})]
    ).values()

    assert place.kind is PlaceKind.FILE
    assert place.coordinates.path == "/fictional/config"


def test_a_file_place_keeps_its_paths(tmp_path: Path):
    coordinates = {"paths": ["/fictional/a", "~/b", "work/c"]}

    places = given.loaded(tmp_path, [given.an_entry(kind="file", coordinates=coordinates)])
    [place] = places.values()

    assert place.coordinates.paths == ("/fictional/a", "~/b", "work/c")


def test_reaches_round_trip(tmp_path: Path):
    [place] = given.loaded(
        tmp_path, [given.an_entry(reaches=["arbitrary_read", "internal_fetch"])]
    ).values()

    assert place.reaches == frozenset({"arbitrary_read", "internal_fetch"})


@pytest.mark.parametrize("kind", ["account", "hostname", "unplaceable"])
def test_an_empty_coordinate_kind_loads(tmp_path: Path, kind: str):
    [place] = given.loaded(tmp_path, [given.an_entry(kind=kind, coordinates={})]).values()

    assert place.kind is PlaceKind(kind)


@pytest.mark.parametrize(
    ("kind", "coordinates"),
    [
        ("file", {"path": "/fictional/config"}),
        ("file", {"path": "~/fictional-secret"}),
        ("file", {"path": "$HOME/fictional-secret"}),
        ("file", {"path": "data/fictional"}),
        ("file", {"path": "data/fictional~"}),
        ("file", {"path": "/fictional/<account>/config"}),
        ("http_endpoint", {"host": "fictional.internal", "path": "/latest"}),
        ("http_endpoint", {"host": "192.0.2.10", "path": "/latest/meta"}),
    ],
    ids=[
        "absolute",
        "home_tilde",
        "home_variable",
        "relative",
        "relative_trailing_tilde",
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
    ("host", "expected"), [("META.Fict", "meta.fict"), ("LOCALHOST", "localhost")]
)
def test_an_endpoint_host_loads_lower_cased(tmp_path: Path, host: str, expected: str):
    coordinates = {"host": host, "path": "/fictional"}

    places = given.loaded(tmp_path, [given.an_entry(kind="http_endpoint", coordinates=coordinates)])

    assert places["place-1"].coordinates.host == expected


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


@pytest.mark.parametrize(
    "path",
    [
        "$XDG_CONFIG_HOME/x",
        "${HOME}/x",
        "/home/$USER/x",
        "%APPDATA%\\x",
        "C:/Users/x",
        "file:///x",
        "~other/x",
        "~",
        "$HOME",
        "data\\config",
    ],
)
def test_a_rejected_file_notation_raises_naming_the_entry(tmp_path: Path, path: str):
    with pytest.raises(ValueError, match="place-1"):
        given.loaded(tmp_path, [given.an_entry(kind="file", coordinates={"path": path})])


def test_an_unknown_reachable_by_token_raises(tmp_path: Path):
    with pytest.raises(ValueError, match=r"place-1.*reachable_by"):
        given.loaded(tmp_path, [given.an_entry(reaches=["arbitrary_read", "mystery_token"])])


@pytest.mark.parametrize("missing", ["source", "category", "technique_ids", "place"])
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


@pytest.mark.parametrize("kind", ["git_remote_url", "git_history", "dotenv"])
def test_a_layout_place_keeps_its_anchor_and_relpath(tmp_path: Path, kind: str):
    coordinates = {"anchor": "project_bare", "relpath": "sub/fictional"}

    [place] = given.loaded(
        tmp_path, [given.an_entry(kind=kind, source="layout", coordinates=coordinates)]
    ).values()

    assert place.kind is PlaceKind(kind)
    assert place.coordinates.anchor is LayoutAnchor.PROJECT_BARE
    assert place.coordinates.relpath == "sub/fictional"


@pytest.mark.parametrize(
    "coordinates",
    [
        {"anchor": "workspace"},
        {"relpath": "config"},
        {"anchor": "nowhere", "relpath": "config"},
        {"anchor": "workspace", "relpath": "/config"},
        {"anchor": "workspace", "relpath": "../config"},
        {"anchor": "workspace", "relpath": "$HOME/config"},
        {"anchor": "workspace", "relpath": "a/*.log"},
        {"anchor": "workspace", "relpath": ""},
        {"anchor": "workspace", "relpath": "config", "extra": "x"},
    ],
    ids=[
        "no_relpath",
        "no_anchor",
        "unknown_anchor",
        "absolute_relpath",
        "dotdot_segment",
        "variable_relpath",
        "glob_relpath",
        "empty_relpath",
        "extra_key",
    ],
)
def test_a_rejected_layout_coordinate_raises_naming_the_entry(
    tmp_path: Path, coordinates: dict[str, Any]
):
    with pytest.raises(ValueError, match="place-1"):
        given.loaded(
            tmp_path, [given.an_entry(kind="dotenv", source="layout", coordinates=coordinates)]
        )


@pytest.mark.parametrize(
    ("kind", "source", "coordinates"),
    [
        ("dotenv", "catalogue", {"anchor": "workspace", "relpath": ".env"}),
        ("file", "layout", {"path": "/fictional/config"}),
    ],
    ids=["layout_kind_catalogue_source", "catalogue_kind_layout_source"],
)
def test_a_kind_that_does_not_match_its_source_raises(
    tmp_path: Path, kind: str, source: str, coordinates: dict[str, Any]
):
    with pytest.raises(ValueError, match=r"place-1.*source"):
        given.loaded(tmp_path, [given.an_entry(kind=kind, source=source, coordinates=coordinates)])


def test_an_unknown_source_raises(tmp_path: Path):
    with pytest.raises(ValueError, match=r"place-1.*source"):
        given.loaded(tmp_path, [given.an_entry(source="mystery")])
