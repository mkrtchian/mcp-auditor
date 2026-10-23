from typing import Any


def bound_strictly(body: dict[str, Any]) -> None:
    assert body["text"]["format"]["strict"] is True


def bound_loosely(body: dict[str, Any]) -> None:
    assert body["text"]["format"]["strict"] is False


def payload_arguments_stay_open(body: dict[str, Any]) -> None:
    schema = body["text"]["format"]["schema"]
    payload = schema.get("$defs", {}).get("AuditPayload", schema)
    assert payload["properties"]["arguments"].get("additionalProperties") is not False
