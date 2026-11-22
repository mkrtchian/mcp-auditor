import json
from pathlib import Path
from typing import Any

# The report's no-proof guarantee, held by the result file too.
PROOF_FIELDS = {"evidence", "category", "judge_input", "judge", "verdict", "status", "miss_kind"}


def result_keys(path: Path) -> set[str]:
    return _keys(json.loads(path.read_text()))


def _keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        entries: dict[str, Any] = value
        return set(entries).union(*(_keys(item) for item in entries.values()))
    if isinstance(value, list):
        items: list[Any] = value
        return set[str]().union(*(_keys(item) for item in items))
    return set()
