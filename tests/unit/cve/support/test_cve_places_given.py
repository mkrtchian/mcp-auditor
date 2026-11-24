"""Fictional places and files for the loader tests. No real coordinate appears here:
every path, host and name is invented, drawn from the documentation ranges where it is an
address, so nothing can be mistaken for the imported data.
"""

import json
from pathlib import Path
from typing import Any

from evals.cve.places import Place, load_places


def an_entry(
    place_id: str = "place-1",
    *,
    kind: str = "file",
    coordinates: dict[str, Any] | None = None,
    reaches: list[str] | None = None,
    source: str = "catalogue",
) -> dict[str, Any]:
    return {
        "id": place_id,
        "source": source,
        "family": "fictional-family",
        "reachable_by": ["arbitrary_read"] if reaches is None else reaches,
        "kind": kind,
        "coordinates": {"path": "/fictional/default"} if coordinates is None else coordinates,
        "category": "fictional-category",
        "technique_ids": ["T0000"],
        "place": "a fictional place description",
    }


def loaded(tmp_path: Path, entries: list[dict[str, Any]]) -> dict[str, Place]:
    path = tmp_path / "places.json"
    path.write_text(json.dumps(entries))
    return load_places(path)
