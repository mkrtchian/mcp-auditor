"""Fictional places and files for the loader tests. No real coordinate appears here:
every path, host and name is invented, drawn from the documentation ranges where it is an
address, so nothing can be mistaken for the imported data.
"""

import json
from pathlib import Path
from typing import Any

from evals.cve_places import Place, load_places

TEST_HOME = "/home/fictional-user"
TEST_WORKDIR = "/srv/fictional-workdir"
TEST_PLACEHOLDER = "fictional-segment"


def an_entry(
    entry_id: str = "place-1",
    *,
    kind: str = "file",
    coordinates: dict[str, Any] | None = None,
    reachable_by: list[str] | None = None,
    family: str = "fictional-family",
) -> dict[str, Any]:
    return {
        "id": entry_id,
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


def resolve_file_path(path: str) -> str:
    """Substitute a home prefix, the working directory and one placeholder by fixed fictional
    values, so a real coordinate can be checked absolute without the test reading its value.
    """
    segments = (
        TEST_PLACEHOLDER if _is_placeholder(segment) else segment for segment in path.split("/")
    )
    resolved = "/".join(segments)
    if resolved.startswith("~/"):
        resolved = f"{TEST_HOME}/{resolved[2:]}"
    elif resolved.startswith("$HOME/"):
        resolved = f"{TEST_HOME}/{resolved[len('$HOME/') :]}"
    if not resolved.startswith("/"):
        resolved = f"{TEST_WORKDIR}/{resolved}"
    return resolved


def _is_placeholder(segment: str) -> bool:
    return segment.startswith("<") and segment.endswith(">")
