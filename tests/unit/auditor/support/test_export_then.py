import json
from pathlib import Path

SINGLE_STEP_FIELDS = {
    "run_index",
    "type",
    "tool_name",
    "tool_description",
    "category",
    "description",
    "arguments",
    "response",
    "error",
    "verdict",
    "justification",
}

CHAIN_FIELDS = {
    "run_index",
    "type",
    "tool_name",
    "tool_description",
    "category",
    "goal",
    "steps",
    "verdict",
    "justification",
}


def exported_records(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text().strip().splitlines()]


def every_record_is_a_single_step_with(records: list[dict[str, object]], fields: set[str]) -> None:
    assert records
    for record in records:
        assert set(record) == fields
        assert record["type"] == "single_step"
