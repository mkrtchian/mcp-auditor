from collections import Counter
from collections.abc import Collection
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, StringConstraints

from evals.gate import Cell, CellComparison, CellOutcome
from evals.honeypots import REPO_ROOT

DECLARED_FLIPS_PATH = REPO_ROOT / "evals" / "declared_flips.json"


class Suite(StrEnum):
    HONEYPOT = "honeypot"


class DeclaredFlip(BaseModel):
    """A cell a change to the system under test is expected to lose, declared in the
    commit that makes the change (ADR 020). `base` is that commit's parent."""

    suite: Suite
    key: str
    mechanism: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
    base: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    runs_seen: list[str]


class DeclaredFlipsFile(BaseModel):
    entries: list[DeclaredFlip]


@dataclass(frozen=True)
class ActiveDeclarations:
    keys: frozenset[str] = frozenset()
    ignored: frozenset[str] = frozenset()


def load_declared_flips(path: Path) -> list[DeclaredFlip]:
    if not path.exists():
        return []
    return DeclaredFlipsFile.model_validate_json(path.read_text()).entries


def entries_of_commit(
    entries: list[DeclaredFlip], suite: Suite, parent: str | None
) -> list[DeclaredFlip]:
    if parent is None:
        return []
    return [entry for entry in entries if entry.suite == suite and entry.base == parent]


def declaration_problems(entries: list[DeclaredFlip], known_keys: Collection[str]) -> list[str]:
    counts = Counter(entry.key for entry in entries)
    unknown = [
        f"declared flip {key} names no cell of the ground truth"
        for key in counts
        if key not in known_keys
    ]
    twice = [
        f"declared flip {key} is named {count} times" for key, count in counts.items() if count > 1
    ]
    return unknown + twice


def active_declarations(entries: list[DeclaredFlip], dirty: bool) -> ActiveDeclarations:
    keys = frozenset(entry.key for entry in entries)
    return ActiveDeclarations(ignored=keys) if dirty else ActiveDeclarations(keys=keys)


def apply_declarations(
    cells: dict[Cell, CellComparison], declared: frozenset[Cell]
) -> dict[Cell, CellComparison]:
    return {
        cell: _declared(comparison) if cell in declared else comparison
        for cell, comparison in cells.items()
    }


def _declared(comparison: CellComparison) -> CellComparison:
    if comparison.outcome != CellOutcome.FLIP:
        return comparison
    return comparison.model_copy(update={"outcome": CellOutcome.DECLARED})
