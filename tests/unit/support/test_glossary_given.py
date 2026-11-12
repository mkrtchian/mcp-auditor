import re
from dataclasses import dataclass
from pathlib import Path

from tests.unit.support.retired_word_scan import AllowedLine, Exemptions, RetiredWord, Scan

THE_WORD = "oldterm"
THE_WORD_ID = "fixture-word"
FIXTURE_WORDS = (RetiredWord(THE_WORD_ID, rf"\b{THE_WORD}\b", re.IGNORECASE, "2"),)
NO_EXEMPTION = Exemptions()
A_LINE_WITH_THE_WORD = f"A line that still says {THE_WORD}.\n"


@dataclass(frozen=True)
class FixtureFile:
    path: str
    content: str


LIVING_CUTS = (
    FixtureFile(
        "CHANGELOG.md",
        f"# Changelog\n\n## [Unreleased]\n\n- Says {THE_WORD}.\n\n## [0.1.0] - 2026-01-01\n",
    ),
    FixtureFile("docs/labeling-log.md", f"# Log\n\n## Rubric\n\n{THE_WORD}\n\n## Entries\n"),
    FixtureFile(
        "docs/detection-suite-log.md", f"# Log\n\nThe {THE_WORD} preamble.\n\n- 2026-01-01: x.\n"
    ),
)

HISTORICAL_TEXTS = (
    FixtureFile("docs/adr/001-a-decision.md", A_LINE_WITH_THE_WORD),
    FixtureFile("plans/2026-01-01_a_plan.md", A_LINE_WITH_THE_WORD),
    FixtureFile("docs/glossary-log.md", A_LINE_WITH_THE_WORD),
    FixtureFile(
        "CHANGELOG.md",
        f"# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-01-01\n\n- Says {THE_WORD}.\n",
    ),
    FixtureFile("docs/labeling-log.md", f"# Log\n\n## Entries\n\n### 2026-01-01\n\n{THE_WORD}\n"),
    FixtureFile("docs/nuisance-suite-log.md", f"# Log\n\nPreamble.\n\n- 2026-01-01: {THE_WORD}.\n"),
    FixtureFile("evals/baselines/a_baseline.json", f'{{"word": "{THE_WORD}"}}\n'),
    FixtureFile("tests/unit/support/a_golden.json", f'{{"word": "{THE_WORD}"}}\n'),
)


def a_tree(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


def an_entry_for(path_glob: str, line_substring: str) -> AllowedLine:
    return AllowedLine(path_glob, THE_WORD_ID, line_substring, "a fixture entry")


def hit_paths(result: Scan) -> list[str]:
    return sorted({hit.path for hit in result.violations})
