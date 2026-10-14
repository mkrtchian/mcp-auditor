"""Fictional places and files for the loader tests. No real coordinate appears here:
every path, host and name is invented, drawn from the documentation ranges where it is an
address, so nothing can be mistaken for the imported data.
"""

import json
from pathlib import Path
from typing import Any

from evals.cve_places import Place, load_places


def an_entry(
    entry_id: str = "place-1",
    *,
    kind: str = "file",
    coordinates: dict[str, Any] | None = None,
    reachable_by: list[str] | None = None,
    family: str = "fictional-family",
    source: str = "catalogue",
) -> dict[str, Any]:
    return {
        "id": entry_id,
        "source": source,
        "family": family,
        "reachable_by": ["arbitrary_read"] if reachable_by is None else reachable_by,
        "kind": kind,
        "coordinates": {"path": "/fictional/default"} if coordinates is None else coordinates,
        "category": "fictional-category",
        "technique_ids": ["T0000"],
        "place": "a fictional place description",
    }


def written(tmp_path: Path, entries: list[dict[str, Any]]) -> Path:
    path = tmp_path / "places.json"
    path.write_text(json.dumps(entries))
    return path


def loaded(tmp_path: Path, entries: list[dict[str, Any]]) -> dict[str, Place]:
    return load_places(written(tmp_path, entries))
