"""The public places file (`evals/holdout_places.json`) and its loader.

The file is the machine-readable projection of the rule's frozen list, copied verbatim from
upstream and never written by a tool here. A unit test pins its SHA-256, so a silent edit of
the imported data fails the suite.

`load_places` parses it into frozen `Place` value objects keyed by `id`, keeping only the
fields a consumer reads. It validates each entry strictly: the exact top-level fields, the
closed `reachable_by` vocabulary, the per-kind coordinate keys, and the coordinate notations
the rule's source manifest uses. Any other notation raises, naming the entry and the failing
property but never the value, so the schema test can run on the real file without reading a
single coordinate. The composition root loads the file once and injects the mapping; every
consumer, and every test, receives `Places` as an argument and passes fictional records.
"""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import AddressValueError, IPv4Address
from pathlib import Path
from typing import Any, cast

HOLDOUT_PLACES = Path(__file__).parent / "holdout_places.json"

REACHABLE_BY = frozenset({"arbitrary_read", "command_execution", "internal_fetch"})

_ENTRY_FIELDS = frozenset(
    {"id", "family", "reachable_by", "kind", "coordinates", "category", "technique_ids", "place"}
)
_GLOB_CHARS = "*?[]"
_PLACEHOLDER = re.compile(r"^<[^<>/]+>$")
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")


class PlantKind(StrEnum):
    FILE = "file"
    ENV = "env"
    ACCOUNT = "account"
    HOSTNAME = "hostname"
    HTTP_ENDPOINT = "http_endpoint"
    UNPLACEABLE = "unplaceable"


@dataclass(frozen=True)
class Coordinates:
    kind: PlantKind
    path: str | None = None
    paths: tuple[str, ...] | None = None
    name: str | None = None
    host: str | None = None


@dataclass(frozen=True)
class Place:
    id: str
    family: str
    reachable_by: frozenset[str]
    kind: PlantKind
    coordinates: Coordinates


Places = Mapping[str, Place]


def load_places(path: Path) -> dict[str, Place]:
    data: Any = json.loads(path.read_text())
    if not isinstance(data, list):
        raise ValueError("the places file is not a list of entries")
    places: dict[str, Place] = {}
    for entry in cast(list[Any], data):
        place = _place(entry)
        if place.id in places:
            raise ValueError(f"{place.id}: duplicate id")
        places[place.id] = place
    return places


def kept_records(ids: tuple[str, ...], places: Places) -> tuple[Place, ...]:
    """The loaded records of a target's kept ids, in order. Raises on an id the mapping
    lacks, naming it: an unknown kept id is a configuration error, not a skipped run."""
    records: list[Place] = []
    for place_id in ids:
        if place_id not in places:
            raise ValueError(f"{place_id}: no such place in the loaded mapping")
        records.append(places[place_id])
    return tuple(records)


def _place(entry: Any) -> Place:
    if not isinstance(entry, dict):
        raise ValueError("a places entry is not an object")
    fields = cast(dict[str, Any], entry)
    entry_id = fields.get("id")
    if not isinstance(entry_id, str) or not entry_id:
        raise ValueError("a places entry has no string id")
    _check_entry_fields(entry_id, set(fields))
    kind = _kind(entry_id, fields["kind"])
    return Place(
        id=entry_id,
        family=_string(entry_id, "family", fields["family"]),
        reachable_by=_reachable_by(entry_id, fields["reachable_by"]),
        kind=kind,
        coordinates=_coordinates(entry_id, kind, fields["coordinates"]),
    )


def _check_entry_fields(entry_id: str, fields: set[str]) -> None:
    missing = _ENTRY_FIELDS - fields
    if missing:
        raise ValueError(f"{entry_id}: missing top-level field '{sorted(missing)[0]}'")
    extra = fields - _ENTRY_FIELDS
    if extra:
        raise ValueError(f"{entry_id}: unexpected top-level field '{sorted(extra)[0]}'")


def _kind(entry_id: str, value: Any) -> PlantKind:
    if not isinstance(value, str):
        raise ValueError(f"{entry_id}: kind is not a string")
    try:
        return PlantKind(value)
    except ValueError:
        raise ValueError(f"{entry_id}: unknown kind") from None


def _reachable_by(entry_id: str, value: Any) -> frozenset[str]:
    if not isinstance(value, list):
        raise ValueError(f"{entry_id}: reachable_by is not a list")
    tokens: set[str] = set()
    for token in cast(list[Any], value):
        if not isinstance(token, str):
            raise ValueError(f"{entry_id}: reachable_by has a non-string token")
        tokens.add(token)
    if tokens - REACHABLE_BY:
        raise ValueError(f"{entry_id}: reachable_by has a token outside the closed vocabulary")
    return frozenset(tokens)


def _coordinates(entry_id: str, kind: PlantKind, value: Any) -> Coordinates:
    if not isinstance(value, dict):
        raise ValueError(f"{entry_id}: coordinates is not an object")
    keys = set(cast(dict[str, Any], value))
    raw = cast(dict[str, Any], value)
    if kind is PlantKind.FILE:
        return _file_coordinates(entry_id, keys, raw)
    if kind is PlantKind.ENV:
        _require_keys(entry_id, keys, {"name"})
        return Coordinates(kind, name=_string(entry_id, "name", raw["name"]))
    if kind is PlantKind.HTTP_ENDPOINT:
        _require_keys(entry_id, keys, {"host", "path"})
        return Coordinates(
            kind,
            host=_endpoint_host(entry_id, raw["host"]),
            path=_endpoint_path(entry_id, raw["path"]),
        )
    _require_keys(entry_id, keys, set())
    return Coordinates(kind)


def _file_coordinates(entry_id: str, keys: set[str], raw: dict[str, Any]) -> Coordinates:
    if keys == {"path"}:
        path = _string(entry_id, "path", raw["path"])
        _check_file_notation(entry_id, path)
        return Coordinates(PlantKind.FILE, path=path)
    if keys == {"paths"}:
        paths = _string_list(entry_id, "paths", raw["paths"])
        for path in paths:
            _check_file_notation(entry_id, path)
        return Coordinates(PlantKind.FILE, paths=tuple(paths))
    raise ValueError(f"{entry_id}: file coordinates need exactly 'path' or 'paths'")


def _endpoint_host(entry_id: str, value: Any) -> str:
    host = _string(entry_id, "host", value)
    if not is_endpoint_host(host):
        raise ValueError(f"{entry_id}: http_endpoint host is not a bare DNS name or IPv4 literal")
    return host


def _endpoint_path(entry_id: str, value: Any) -> str:
    path = _string(entry_id, "path", value)
    if not path.startswith("/"):
        raise ValueError(f"{entry_id}: http_endpoint path is not absolute")
    return path


def _check_file_notation(entry_id: str, path: str) -> None:
    if any(char in path for char in _GLOB_CHARS):
        raise ValueError(f"{entry_id}: file coordinate uses a glob")
    placeholders = 0
    for segment in path.split("/"):
        if "<" in segment or ">" in segment:
            if not _PLACEHOLDER.fullmatch(segment):
                raise ValueError(f"{entry_id}: file coordinate has a malformed placeholder")
            placeholders += 1
    if placeholders > 1:
        raise ValueError(f"{entry_id}: file coordinate has more than one placeholder")


def is_endpoint_host(host: str) -> bool:
    """A bare DNS name or an IPv4 literal: no port, no scheme, no bracket, no IPv6."""
    if any(char in host for char in ":/[]"):
        return False
    return _is_ipv4(host) or _is_dns_name(host)


def _is_ipv4(host: str) -> bool:
    try:
        IPv4Address(host)
    except AddressValueError:
        return False
    return True


def _is_dns_name(host: str) -> bool:
    if len(host) > 253:
        return False
    labels = host.split(".")
    return all(_DNS_LABEL.fullmatch(label) is not None for label in labels)


def _string(entry_id: str, prop: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{entry_id}: {prop} is not a non-empty string")
    return value


def _string_list(entry_id: str, prop: str, value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{entry_id}: {prop} is not a non-empty list")
    return [_string(entry_id, prop, item) for item in cast(list[Any], value)]


def _require_keys(entry_id: str, keys: set[str], expected: set[str]) -> None:
    if keys != expected:
        raise ValueError(f"{entry_id}: coordinate keys are not exactly {sorted(expected)}")
