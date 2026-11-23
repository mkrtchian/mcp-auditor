import re
from dataclasses import dataclass
from pathlib import Path

from evals.cve.census.exclusions import EXCLUDED_SERVERS
from evals.judge.fixture import JudgeCase

_HONEYPOT_RUN_LENGTH = 3

# The excluded-server corpus fires on a whole-word match of the full server text, or a shared
# contiguous run of five or more whole words. This is deliberately higher than the honeypot
# corpus's three-word run: a real server's tool descriptions and error text are natural English
# prose that shares short runs with unrelated src prose by coincidence ("does not exist",
# "cannot be read", "is not a", "of a file"); a five-word run makes coincidence implausible, so a
# fire means a genuine copy. The honeypot corpus keeps the three-word run, which its short planted
# literals need.
_SERVER_RUN_LENGTH = 5

# The auditor's own tool name heads every payload marker it plants (`mcp-auditor-probe`, the
# `mcp-auditor-no-such-…` probe paths). A server never emits that name except by echoing our
# payload back, so a run matching it is dropped: the corpus holds the server's text, not ours.
_AUDITOR_MARKER = re.compile(r"mcp-auditor[\w-]*")

_MARKER_CHARACTERS = set("_@./-")


@dataclass(frozen=True)
class Leak:
    path: Path
    literal: str
    matched: str


def honeypot_literal_leaks(constants: list[tuple[Path, str]], literals: set[str]) -> list[Leak]:
    return _leaks_across(constants, literals, _HONEYPOT_RUN_LENGTH)


def server_text_leaks(constants: list[tuple[Path, str]], texts: set[str]) -> list[Leak]:
    return _leaks_across(constants, texts, _SERVER_RUN_LENGTH)


def _leaks_across(
    constants: list[tuple[Path, str]], literals: set[str], run_length: int
) -> list[Leak]:
    prepared_literals = [_Literal.of(literal, run_length) for literal in sorted(literals)]
    return [
        leak
        for path, text in constants
        for leak in _leaks_of(_Constant.of(path, text, run_length), prepared_literals)
    ]


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


def server_corpus_of(cases: list[JudgeCase], servers: dict[str, str]) -> set[str]:
    corpus: set[str] = set()
    for case in cases:
        flaw_id = _flaw_id_of(case)
        if flaw_id not in servers:
            raise LookupError(f"the census does not classify {flaw_id} of case {case.id}")
        if servers[flaw_id] not in EXCLUDED_SERVERS:
            continue
        corpus |= _server_texts_of(case)
    return corpus


def _flaw_id_of(case: JudgeCase) -> str:
    return case.origin.split()[1]


def _server_texts_of(case: JudgeCase) -> set[str]:
    inputs = case.inputs
    payload = [value for value in inputs.arguments.values() if isinstance(value, str)]
    pieces = (inputs.tool_description, inputs.response, inputs.error)
    texts = {
        _without_payload(piece, payload)
        for piece in pieces
        if isinstance(piece, str) and piece != "None"
    }
    return {text for text in texts if is_discriminating(text)}


def _without_payload(text: str, payload: list[str]) -> str:
    for value in payload:
        text = text.replace(value, "")
    return _AUDITOR_MARKER.sub("", text).strip()


def is_discriminating(text: str) -> bool:
    if len(text) < 3:
        return False
    return (
        len(text.split()) >= 2
        or any(character.isupper() or character.isdigit() for character in text)
        or any(character in _MARKER_CHARACTERS for character in text)
    )
