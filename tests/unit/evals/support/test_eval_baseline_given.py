import json
from pathlib import Path

from evals.baseline import Baseline, BaselineStatus, RecordingRef
from tests.unit.evals.support.honeypot_baselines import RECORDED_COMMIT, ObservationRuns, a_baseline

SERVER_SOURCE = '''"""A server with one tool."""

import json


def get_user(user_id: str) -> str:
    """Return the user."""
    return json.dumps({"id": user_id})
'''

CANARY_SOURCE = '''"""Constructs the fingerprinted modules use, one of each."""

import re
from enum import StrEnum
from typing import Any, NamedTuple, Protocol

from pydantic import BaseModel


class Kind(StrEnum):
    FIRST = "first"


class Pair(NamedTuple):
    left: dict[str, Any]
    right: tuple[str, ...]


class Named(Protocol):
    @property
    def name(self) -> str: ...


class Grade(BaseModel):
    kind: Kind
    evidence: str | None = None
    flags: list[str] = []


PATTERNS: tuple[re.Pattern[str], ...] = (re.compile(r"uid=\\d+"),)
TABLE: dict[Kind, frozenset[str]] = {Kind.FIRST: frozenset({"a", "b"})}


def walk(value: Any, limit: int = 3) -> list[str]:
    found = [item for item in value if isinstance(item, str | bytes)]
    best = min(found, key=lambda item: len(item), default=None)
    if best is not None and len(best) > limit:
        raise ValueError(f"too long: {best!r} over {limit}")
    for index, item in enumerate(found):
        yield from (item, str(index))
    with open("/dev/null") as stream:
        stream.read()
    return [*found, *(str(n) for n in range(limit))]


async def fetch(target: Named) -> str:
    try:
        return await target.name
    except (OSError, ValueError) as error:
        return f"{type(error).__name__}"
'''


def a_baseline_file_keyed_replay_rule(tmp_path: Path) -> Path:
    written = a_baseline().model_dump(mode="json")
    written["replay_rule"] = written.pop("retest_rule")
    path = tmp_path / "honeypot.json"
    path.write_text(json.dumps(written))
    return path


def a_confirmation(runs: ObservationRuns) -> Baseline:
    first = RecordingRef(commit=RECORDED_COMMIT, recorded_at="2026-09-23T09:00:00+00:00")
    return a_baseline(status=BaselineStatus.CONFIRMED, runs=runs).model_copy(
        update={"confirms": first}
    )
