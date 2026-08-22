# Refuses generated payloads that are destructive to state, or dangerous to the host
# and the run, before they reach the audited server (ADR 013).
# The list below is enumerated, not complete: it guards against our own generator's
# exuberance, it is not a bypass-resistant boundary.
from dataclasses import dataclass
from typing import Any, cast


def destructive_reason(arguments: dict[str, Any]) -> str | None:
    match = _first_destructive_match(arguments)
    if match is None:
        return None
    construct, pattern = match
    return f"{construct.reason}: {pattern}"


def _first_destructive_match(value: Any) -> tuple["DestructiveConstruct", str] | None:
    if isinstance(value, str):
        return _matching_construct(_without_harmless_sinks(value.lower()))
    if isinstance(value, dict):
        children = list(cast("dict[str, Any]", value).values())
    elif isinstance(value, list):
        children = cast("list[Any]", value)
    else:
        return None
    for child in children:
        match = _first_destructive_match(child)
        if match is not None:
            return match
    return None


def _matching_construct(text: str) -> tuple["DestructiveConstruct", str] | None:
    for construct in DESTRUCTIVE_CONSTRUCTS:
        for pattern in construct.patterns:
            if _contains_as_a_construct(text, pattern):
                return construct, pattern
    return None


def _contains_as_a_construct(text: str, pattern: str) -> bool:
    start = text.find(pattern)
    while start != -1:
        if _right_delimited(text, pattern, start):
            return True
        start = text.find(pattern, start + 1)
    return False


# A flag or an argument delimits a pattern on its right, except "init 0", "init 6" and
# "kill -9 1", whose edge is a bare digit and so matches inside "git init 0auth". Trailing
# letters stay permissive: "rm -rf" must keep matching "rm -rfv".
# Nothing is required on the left. Demanding a boundary there would cost more than it buys:
# an encoded separator is alphanumeric, so "%3Brm -rf /" would stop matching, and a false
# allow is the one error this guard exists to avoid.
def _right_delimited(text: str, pattern: str, start: int) -> bool:
    if not pattern[-1].isdigit():
        return True
    end = start + len(pattern)
    return end == len(text) or not text[end].isalnum()


def _without_harmless_sinks(text: str) -> str:
    for sink in _HARMLESS_SINKS:
        text = text.replace(sink, "")
    return text


_HARMLESS_SINKS = ("/dev/null", "/dev/stdout", "/dev/stderr")


@dataclass(frozen=True)
class DestructiveConstruct:
    reason: str
    patterns: tuple[str, ...]


DESTRUCTIVE_CONSTRUCTS: tuple[DestructiveConstruct, ...] = (
    DestructiveConstruct(
        reason="destructive filesystem command",
        patterns=(
            "rm -rf",
            "rm -fr",
            "rm -r ",
            "rm -f ",
            "rm /",
            "rm ~",
            "rmdir ",
            "shred ",
            "unlink ",
            "mv /",
        ),
    ),
    DestructiveConstruct(
        reason="output redirect overwriting a file",
        patterns=("> /", ">> /", "> ~", ">> ~"),
    ),
    DestructiveConstruct(
        reason="recursive permission change",
        patterns=("chmod -r", "chown -r"),
    ),
    DestructiveConstruct(
        reason="destructive disk operation",
        patterns=("mkfs.", "mkfs ", "dd of=", "of=/dev/", "truncate -s"),
    ),
    DestructiveConstruct(
        reason="destructive SQL statement",
        patterns=("drop table", "drop database", "truncate table", "delete from "),
    ),
    DestructiveConstruct(
        reason="forced version-control write",
        patterns=("push --force", "push -f ", "checkout --force", "reset --hard", "clean -fd"),
    ),
    DestructiveConstruct(
        reason="host availability command",
        patterns=(
            "shutdown -",
            "shutdown now",
            "sudo shutdown",
            "reboot -",
            "sudo reboot",
            "sudo poweroff",
            "init 0",
            "init 6",
            "kill -9 1",
        ),
    ),
    DestructiveConstruct(
        reason="fork bomb",
        patterns=(":(){", ":|:&", ":(){:|:&};:"),
    ),
)
