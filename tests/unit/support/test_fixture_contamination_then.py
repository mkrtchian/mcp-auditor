import re
from dataclasses import dataclass
from pathlib import Path

_HONEYPOT_RUN_LENGTH = 3

# The excluded-server corpus fires on a whole-word match of the full server text, or a shared
# contiguous run of five or more whole words. This is deliberately higher than the honeypot
# corpus's three-word run: a real server's tool descriptions and error text are natural English
# prose that shares short runs with unrelated src prose by coincidence ("does not exist",
# "cannot be read", "is not a", "of a file"); a five-word run makes coincidence implausible, so a
# fire means a genuine copy. The honeypot corpus keeps the three-word run, which its short planted
# literals need.
_SERVER_RUN_LENGTH = 5


@dataclass(frozen=True)
class Leak:
    path: Path
    literal: str
    matched: str


def no_constant_contains_any_substring(
    constants: list[tuple[Path, str]], substrings: set[str]
) -> None:
    # A plain substring check, not the whole-word honeypot matcher: a layout path is a literal
    # fragment that must not appear anywhere in a shipped constant.
    leaks = [
        (path, substring)
        for path, text in constants
        for substring in sorted(substrings)
        if substring in text
    ]
    assert not leaks, "Shipped constants name layout literals:\n" + "\n".join(
        f"{path}: {substring}" for path, substring in leaks
    )


def no_constant_contains_any_of(constants: list[tuple[Path, str]], literals: set[str]) -> None:
    _assert_no_leaks(constants, literals, _HONEYPOT_RUN_LENGTH, "honeypot literals")


def no_constant_contains_any_server_text(
    constants: list[tuple[Path, str]], texts: set[str]
) -> None:
    _assert_no_leaks(constants, texts, _SERVER_RUN_LENGTH, "excluded-server text")


def _assert_no_leaks(
    constants: list[tuple[Path, str]], literals: set[str], run_length: int, noun: str
) -> None:
    prepared_literals = [_Literal.of(literal, run_length) for literal in sorted(literals)]
    leaks = [
        leak
        for path, text in constants
        for leak in _leaks_of(_Constant.of(path, text, run_length), prepared_literals)
    ]
    assert not leaks, f"Shipped constants name {noun}:\n" + "\n".join(
        f"{leak.path}: {leak.literal} ({leak.matched})" for leak in leaks
    )


# The regex and the word runs of each side are computed once, not once per pair: the check
# crosses every constant of src with every literal.
@dataclass(frozen=True)
class _Literal:
    text: str
    whole_word: re.Pattern[str]
    word_runs: frozenset[str]

    @staticmethod
    def of(text: str, run_length: int) -> "_Literal":
        whole_word = re.compile(rf"(?<!\w){re.escape(text)}(?!\w)")
        return _Literal(text, whole_word, frozenset(_word_runs(text, run_length)))


@dataclass(frozen=True)
class _Constant:
    path: Path
    text: str
    word_runs: list[str]

    @staticmethod
    def of(path: Path, text: str, run_length: int) -> "_Constant":
        return _Constant(path, text, _word_runs(text, run_length))


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


def _word_runs(text: str, run_length: int) -> list[str]:
    words = re.findall(r"[a-z0-9_]+", text.lower())
    return [
        " ".join(words[start : start + run_length]) for start in range(len(words) - run_length + 1)
    ]
