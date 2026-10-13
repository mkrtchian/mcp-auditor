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
    prepared_literals = [_Literal.of(literal) for literal in sorted(literals)]
    leaks = [
        leak
        for path, text in constants
        for leak in _leaks_of(_Constant.of(path, text), prepared_literals)
    ]
    assert not leaks, "Shipped constants name honeypot literals:\n" + "\n".join(
        f"{leak.path}: {leak.literal} ({leak.matched})" for leak in leaks
    )


# The regex and the word runs of each side are computed once, not once per pair: the check
# crosses every constant of src with every honeypot literal.
@dataclass(frozen=True)
class _Literal:
    text: str
    whole_word: re.Pattern[str]
    word_runs: frozenset[str]

    @staticmethod
    def of(text: str) -> "_Literal":
        whole_word = re.compile(rf"(?<!\w){re.escape(text)}(?!\w)")
        return _Literal(text, whole_word, frozenset(_word_runs(text)))


@dataclass(frozen=True)
class _Constant:
    path: Path
    text: str
    word_runs: list[str]

    @staticmethod
    def of(path: Path, text: str) -> "_Constant":
        return _Constant(path, text, _word_runs(text))


def _leaks_of(constant: _Constant, literals: list[_Literal]) -> list[Leak]:
    return [leak for literal in literals if (leak := _leak_of(constant, literal)) is not None]


def _leak_of(constant: _Constant, literal: _Literal) -> Leak | None:
    whole = literal.whole_word.search(constant.text)
    if whole:
        return Leak(constant.path, literal.text, whole.group())
    shared = next((run for run in constant.word_runs if run in literal.word_runs), None)
    if shared:
        return Leak(constant.path, literal.text, shared)
    return None


def _word_runs(text: str) -> list[str]:
    words = re.findall(r"[a-z0-9_]+", text.lower())
    return [
        " ".join(words[start : start + _SHARED_RUN_LENGTH])
        for start in range(len(words) - _SHARED_RUN_LENGTH + 1)
    ]
