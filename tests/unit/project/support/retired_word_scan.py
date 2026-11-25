"""The retired-word scan: which text of the repository is living, and what it may no longer say.

Living text is the code under `src/`, `evals/` and `tests/` with its file paths, README.md,
CLAUDE.md, CONTRIBUTING.md, `.env.example`, the `[Unreleased]` section of CHANGELOG.md, the
glossary, `docs/usage.md`, `docs/evals.md`, the two rules, the preambles of the three logs and
`.github/workflows/`. Everything else is historical and never read: ADRs, plans, the glossary
log, the published CHANGELOG sections, the dated log entries, and the committed records (every
JSON file under the code roots), key files, binaries and the files above 100 KB under the code
roots, which embed a device capture. The modules that hold the patterns and the exemptions are
skipped too. A test name is also read with `_` as a space, so a retired word inside a snake_case
name is found.
"""

import bisect
import fnmatch
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RetiredWord:
    id: str
    regex: str
    flags: re.RegexFlag

    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.regex, self.flags)


@dataclass(frozen=True)
class AllowedLine:
    path_glob: str
    pattern_id: str
    line_substring: str
    reason: str

    def allows(self, hit: "Hit") -> bool:
        return (
            hit.pattern_id == self.pattern_id
            and fnmatch.fnmatch(hit.path, self.path_glob)
            and self.line_substring in hit.line
        )


@dataclass(frozen=True)
class Hit:
    path: str
    line_number: int  # 0 for the file path itself
    pattern_id: str
    line: str


@dataclass(frozen=True)
class Scan:
    violations: tuple[Hit, ...]
    stale_entries: tuple[AllowedLine, ...]


def scan(root: Path, words: tuple[RetiredWord, ...], allowlist: tuple[AllowedLine, ...]) -> Scan:
    _refuse_unknown_ids(words, allowlist)
    hits = [hit for text in _living_texts(root) for hit in _hits_in(text, words)]
    violations = tuple(hit for hit in hits if not any(entry.allows(hit) for entry in allowlist))
    stale = tuple(entry for entry in allowlist if not any(entry.allows(hit) for hit in hits))
    return Scan(violations, stale)


def imports_the_glossary(root: Path) -> bool:
    claude_md = root / "CLAUDE.md"
    return claude_md.is_file() and "@docs/glossary.md" in claude_md.read_text().splitlines()


def _refuse_unknown_ids(words: tuple[RetiredWord, ...], allowlist: tuple[AllowedLine, ...]) -> None:
    known = {word.id for word in words}
    named = {entry.pattern_id for entry in allowlist}
    if unknown := sorted(named - known):
        raise ValueError(f"exemptions name unknown pattern ids: {unknown}")


@dataclass(frozen=True)
class _LivingText:
    path: str
    first_line_number: int
    text: str
    path_counts: bool


def _living_texts(root: Path) -> Iterator[_LivingText]:
    for relative in _WHOLE_FILES:
        yield from _whole(root, relative, path_counts=False)
    for relative, cut in _CUT_FILES.items():
        yield from _cut(root, relative, cut)
    for relative in _code_files(root):
        if not _is_oversized(root / relative):
            yield from _whole(root, relative, path_counts=True)
    for relative in _files_under(root, _WORKFLOWS):
        yield from _whole(root, relative, path_counts=False)


def oversized_files(root: Path) -> tuple[str, ...]:
    return tuple(relative for relative in _code_files(root) if _is_oversized(root / relative))


_WHOLE_FILES = (
    "README.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    ".env.example",
    "docs/glossary.md",
    "docs/usage.md",
    "docs/evals.md",
    "docs/detection-suite-rule.md",
    "docs/nuisance-suite-rule.md",
)
_CODE_ROOTS = ("src", "evals", "tests")
_WORKFLOWS = ".github/workflows"
_SKIPPED = (
    "tests/integration/committed/project/support/retired_words.py",
    "tests/integration/committed/project/support/retired_word_exemptions.py",
)
_RECORD_AND_KEY_SUFFIXES = (".json", ".pem", ".key")
_SIZE_BOUND = 100_000


def _code_files(root: Path) -> Iterator[str]:
    for directory in _CODE_ROOTS:
        for relative in _files_under(root, directory):
            if relative not in _SKIPPED and not _is_record_or_key(relative):
                yield relative


def _is_oversized(path: Path) -> bool:
    return path.stat().st_size > _SIZE_BOUND


def _is_record_or_key(relative: str) -> bool:
    return relative.endswith(_RECORD_AND_KEY_SUFFIXES)


def _files_under(root: Path, directory: str) -> Iterator[str]:
    for path in sorted((root / directory).rglob("*")):
        relative = path.relative_to(root)
        hidden = any(part.startswith(".") or part == "__pycache__" for part in relative.parts[1:])
        if path.is_file() and not hidden:
            yield relative.as_posix()


def _whole(root: Path, relative: str, path_counts: bool) -> Iterator[_LivingText]:
    path = root / relative
    if not path.is_file():
        return
    try:
        text = path.read_text()
    except UnicodeDecodeError:
        return
    yield _LivingText(relative, 1, text, path_counts)


# A cut keeps the lines from the first that `starts` accepts up to, not including, the first
# later line that `ends` accepts.
@dataclass(frozen=True)
class _Cut:
    starts: Callable[[str], bool]
    ends: Callable[[str], bool]


def _from_the_top(_: str) -> bool:
    return True


def _is_dated_entry(line: str) -> bool:
    return re.match(r"- \d{4}-\d{2}-\d{2}", line) is not None


_CUT_FILES = {
    "CHANGELOG.md": _Cut(
        starts=lambda line: line.startswith("## [Unreleased]"),
        ends=lambda line: line.startswith("## ["),
    ),
    "docs/labeling-log.md": _Cut(_from_the_top, ends=lambda line: line.startswith("## Entries")),
    "docs/detection-suite-log.md": _Cut(_from_the_top, ends=_is_dated_entry),
    "docs/nuisance-suite-log.md": _Cut(_from_the_top, ends=_is_dated_entry),
}


def _cut(root: Path, relative: str, cut: _Cut) -> Iterator[_LivingText]:
    path = root / relative
    if not path.is_file():
        return
    lines = path.read_text().split("\n")
    start = next((index for index, line in enumerate(lines) if cut.starts(line)), len(lines))
    end = next(
        (index for index in range(start + 1, len(lines)) if cut.ends(lines[index])), len(lines)
    )
    yield _LivingText(relative, start + 1, "\n".join(lines[start:end]), path_counts=False)


def _hits_in(text: _LivingText, words: tuple[RetiredWord, ...]) -> Iterator[Hit]:
    lines = text.text.split("\n")
    line_starts = _line_starts(text.text)
    # In a path, `_`, `/`, `.` and `-` separate words, so the path is also read with spaces.
    path_forms = (text.path, re.sub(r"[_./-]", " ", text.path)) if text.path_counts else ()
    test_names = _test_names(text.text)
    for word in words:
        pattern = word.compiled()
        if any(pattern.search(form) for form in path_forms):
            yield Hit(text.path, 0, word.id, text.path)
        offsets = [match.start() for match in pattern.finditer(text.text)]
        offsets += [offset for offset, name in test_names if pattern.search(name)]
        indexes = sorted({bisect.bisect_right(line_starts, offset) - 1 for offset in offsets})
        for index in indexes:
            yield Hit(text.path, text.first_line_number + index, word.id, lines[index])


def _test_names(text: str) -> list[tuple[int, str]]:
    return [
        (match.start(), match.group(1).replace("_", " "))
        for match in re.finditer(r"\bdef (test_\w+)", text)
    ]


def _line_starts(text: str) -> list[int]:
    starts = [0]
    starts += [match.end() for match in re.finditer("\n", text)]
    return starts
