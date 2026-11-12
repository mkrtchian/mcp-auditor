"""The retired-word scan: which text of the repository is living, and what it may no longer say.

Living text is the code under `src/`, `evals/` and `tests/` with its file paths, README.md,
CLAUDE.md, CONTRIBUTING.md, `.env.example`, the `[Unreleased]` section of CHANGELOG.md, the
glossary, the two rules, the preambles of the three logs and `.github/workflows/`. Everything
else is historical and never read: ADRs, plans, the glossary log, the published CHANGELOG
sections, the dated log entries, and the committed records (every JSON file under the code
roots), key files and binaries. The glossary test, its given module and the modules that hold
the patterns and the exemptions are skipped too.
"""

import bisect
import fnmatch
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class RetiredWord:
    id: str
    regex: str
    flags: re.RegexFlag
    step: str  # the body step of the migration plan that removes the id from the exemptions

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
class Exemptions:
    not_yet_renamed: tuple[str, ...] = ()
    not_yet_migrated: tuple[str, ...] = ()
    allowlist: tuple[AllowedLine, ...] = ()


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


def scan(root: Path, words: tuple[RetiredWord, ...], exemptions: Exemptions) -> Scan:
    _refuse_unknown_ids(words, exemptions)
    hits = [hit for text in living_texts(root) for hit in _hits_in(text, words)]
    violations = tuple(
        hit
        for hit in hits
        if hit.pattern_id not in exemptions.not_yet_renamed
        and hit.path not in exemptions.not_yet_migrated
        and not any(entry.allows(hit) for entry in exemptions.allowlist)
    )
    stale = tuple(
        entry for entry in exemptions.allowlist if not any(entry.allows(hit) for hit in hits)
    )
    return Scan(violations, stale)


def imports_the_glossary(root: Path) -> bool:
    claude_md = root / "CLAUDE.md"
    return claude_md.is_file() and "@docs/glossary.md" in claude_md.read_text().splitlines()


def _refuse_unknown_ids(words: tuple[RetiredWord, ...], exemptions: Exemptions) -> None:
    known = {word.id for word in words}
    named = set(exemptions.not_yet_renamed) | {entry.pattern_id for entry in exemptions.allowlist}
    if unknown := sorted(named - known):
        raise ValueError(f"exemptions name unknown pattern ids: {unknown}")


@dataclass(frozen=True)
class LivingText:
    path: str
    first_line_number: int
    text: str
    path_counts: bool


def living_texts(root: Path) -> Iterator[LivingText]:
    for relative in _WHOLE_FILES:
        yield from _whole(root, relative, path_counts=False)
    for relative, cut in _CUT_FILES.items():
        yield from _cut(root, relative, cut)
    for directory in _CODE_ROOTS:
        for relative in _files_under(root, directory):
            if relative not in _SKIPPED and not _is_record_or_key(relative):
                yield from _whole(root, relative, path_counts=True)
    for relative in _files_under(root, _WORKFLOWS):
        yield from _whole(root, relative, path_counts=False)


_WHOLE_FILES = (
    "README.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    ".env.example",
    "docs/glossary.md",
    "docs/detection-suite-rule.md",
    "docs/nuisance-suite-rule.md",
)
_CODE_ROOTS = ("src", "evals", "tests")
_WORKFLOWS = ".github/workflows"
_SKIPPED = (
    "tests/unit/test_glossary.py",
    "tests/unit/support/test_glossary_given.py",
    "tests/unit/support/retired_words.py",
    "tests/unit/support/retired_word_exemptions.py",
)
_RECORD_AND_KEY_SUFFIXES = (".json", ".pem", ".key")


def _is_record_or_key(relative: str) -> bool:
    return relative.endswith(_RECORD_AND_KEY_SUFFIXES)


def _files_under(root: Path, directory: str) -> Iterator[str]:
    for path in sorted((root / directory).rglob("*")):
        relative = path.relative_to(root)
        hidden = any(part.startswith(".") or part == "__pycache__" for part in relative.parts[1:])
        if path.is_file() and not hidden:
            yield relative.as_posix()


def _whole(root: Path, relative: str, path_counts: bool) -> Iterator[LivingText]:
    path = root / relative
    if not path.is_file():
        return
    try:
        text = path.read_text()
    except UnicodeDecodeError:
        return
    yield LivingText(relative, 1, text, path_counts)


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


def _cut(root: Path, relative: str, cut: _Cut) -> Iterator[LivingText]:
    path = root / relative
    if not path.is_file():
        return
    lines = path.read_text().split("\n")
    start = next((index for index, line in enumerate(lines) if cut.starts(line)), len(lines))
    end = next(
        (index for index in range(start + 1, len(lines)) if cut.ends(lines[index])), len(lines)
    )
    yield LivingText(relative, start + 1, "\n".join(lines[start:end]), path_counts=False)


def _hits_in(text: LivingText, words: tuple[RetiredWord, ...]) -> Iterator[Hit]:
    lines = text.text.split("\n")
    line_starts = _line_starts(text.text)
    # In a path, `_`, `/`, `.` and `-` separate words, so the path is also read with spaces.
    path_forms = (text.path, re.sub(r"[_./-]", " ", text.path)) if text.path_counts else ()
    for word in words:
        pattern = word.compiled()
        if any(pattern.search(form) for form in path_forms):
            yield Hit(text.path, 0, word.id, text.path)
        indexes = sorted(
            {
                bisect.bisect_right(line_starts, match.start()) - 1
                for match in pattern.finditer(text.text)
            }
        )
        for index in indexes:
            yield Hit(text.path, text.first_line_number + index, word.id, lines[index])


def _line_starts(text: str) -> list[int]:
    starts = [0]
    starts += [match.end() for match in re.finditer("\n", text)]
    return starts
