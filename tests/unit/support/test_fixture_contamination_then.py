import re
from dataclasses import dataclass
from pathlib import Path

_SHARED_RUN_LENGTH = 3


@dataclass(frozen=True)
class Leak:
    path: Path
    literal: str
    matched: str


def no_constant_contains_any_of(constants: list[tuple[Path, str]], literals: set[str]) -> None:
    leaks = [
        leak
        for path, constant in constants
        for literal in sorted(literals)
        if (leak := _leak_of(path, constant, literal)) is not None
    ]
    assert not leaks, "Shipped constants name honeypot literals:\n" + "\n".join(
        f"{leak.path}: {leak.literal} ({leak.matched})" for leak in leaks
    )


def _leak_of(path: Path, constant: str, literal: str) -> Leak | None:
    whole = re.search(rf"(?<!\w){re.escape(literal)}(?!\w)", constant)
    if whole:
        return Leak(path, literal, whole.group())
    shared = _shared_word_run(constant, literal)
    if shared:
        return Leak(path, literal, shared)
    return None


def _shared_word_run(constant: str, literal: str) -> str | None:
    literal_runs = _word_runs(literal)
    return next((run for run in _word_runs(constant) if run in literal_runs), None)


def _word_runs(text: str) -> list[str]:
    words = re.findall(r"[a-z0-9_]+", text.lower())
    return [
        " ".join(words[start : start + _SHARED_RUN_LENGTH])
        for start in range(len(words) - _SHARED_RUN_LENGTH + 1)
    ]
