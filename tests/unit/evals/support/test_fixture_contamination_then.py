from pathlib import Path

from tests.unit.evals.support import contamination
from tests.unit.evals.support.contamination import Leak


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
    leaks = contamination.honeypot_literal_leaks(constants, literals)
    assert not leaks, "Shipped constants name honeypot literals:\n" + _listed(leaks)


def no_constant_contains_any_server_text(
    constants: list[tuple[Path, str]], texts: set[str]
) -> None:
    leaks = contamination.server_text_leaks(constants, texts)
    assert not leaks, "Shipped constants name excluded-server text:\n" + _listed(leaks)


def _listed(leaks: list[Leak]) -> str:
    return "\n".join(f"{leak.path}: {leak.literal} ({leak.matched})" for leak in leaks)
