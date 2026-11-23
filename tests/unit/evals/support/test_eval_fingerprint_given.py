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
