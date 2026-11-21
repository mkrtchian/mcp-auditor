from pathlib import Path

import pytest

import tests.unit.project.support.test_glossary_given as given
from evals.honeypots import REPO_ROOT
from tests.unit.support.retired_word_exemptions import EXEMPTIONS
from tests.unit.support.retired_word_scan import (
    AllowedLine,
    Exemptions,
    Scan,
    imports_the_glossary,
    oversized_files,
    scan,
)
from tests.unit.support.retired_words import RETIRED_WORDS


# Scanning the repository takes seconds, so its two tests share one scan.
@pytest.fixture(scope="module")
def repository_scan() -> Scan:
    return scan(REPO_ROOT, RETIRED_WORDS, EXEMPTIONS)


def test_living_files_use_no_retired_word(repository_scan: Scan):
    assert repository_scan.violations == ()


def test_every_allowlist_entry_matches_a_line(repository_scan: Scan):
    assert repository_scan.stale_entries == ()


def test_the_size_bound_skips_only_the_files_embedding_an_android_capture():
    assert oversized_files(REPO_ROOT) == given.THE_ANDROID_DOCKERFILES


def test_claude_md_imports_the_glossary():
    assert imports_the_glossary(REPO_ROOT)


def test_a_retired_word_fires_on_a_living_file(tmp_path: Path):
    root = given.a_tree(tmp_path, {"evals/module.py": given.A_LINE_WITH_THE_WORD})

    result = scan(root, given.FIXTURE_WORDS, given.NO_EXEMPTION)

    assert given.hit_paths(result) == ["evals/module.py"]


def test_a_retired_word_fires_inside_a_test_name(tmp_path: Path):
    root = given.a_tree(tmp_path, {"tests/unit/test_module.py": given.A_TEST_NAMED_WITH_THE_WORD})

    result = scan(root, given.FIXTURE_WORDS, given.NO_EXEMPTION)

    assert given.hit_paths(result) == ["tests/unit/test_module.py"]


def test_a_retired_word_fires_on_a_file_path(tmp_path: Path):
    root = given.a_tree(tmp_path, {f"tests/unit/test_{given.THE_WORD}_given.py": ""})

    result = scan(root, given.FIXTURE_WORDS, given.NO_EXEMPTION)

    assert given.hit_paths(result) == [f"tests/unit/test_{given.THE_WORD}_given.py"]


@pytest.mark.parametrize("living_text", given.LIVING_CUTS, ids=lambda text: text.path)
def test_a_retired_word_fires_in_the_living_part_of_a_cut_file(
    tmp_path: Path, living_text: given.FixtureFile
):
    root = given.a_tree(tmp_path, {living_text.path: living_text.content})

    result = scan(root, given.FIXTURE_WORDS, given.NO_EXEMPTION)

    assert given.hit_paths(result) == [living_text.path]


@pytest.mark.parametrize("historical", given.HISTORICAL_TEXTS, ids=lambda text: text.path)
def test_a_retired_word_is_skipped_in_historical_text(
    tmp_path: Path, historical: given.FixtureFile
):
    root = given.a_tree(tmp_path, {historical.path: historical.content})

    result = scan(root, given.FIXTURE_WORDS, given.NO_EXEMPTION)

    assert result.violations == ()


def test_an_allowlisted_line_passes(tmp_path: Path):
    root = given.a_tree(tmp_path, {"docs/glossary.md": given.A_LINE_WITH_THE_WORD})
    exemptions = Exemptions(allowlist=(given.an_entry_for("docs/*.md", "still says"),))

    result = scan(root, given.FIXTURE_WORDS, exemptions)

    assert (result.violations, result.stale_entries) == ((), ())


def test_an_allowlist_entry_matching_no_line_is_stale(tmp_path: Path):
    root = given.a_tree(tmp_path, {"docs/glossary.md": "A line the word has left.\n"})
    entry = given.an_entry_for("docs/glossary.md", "the word has left")

    result = scan(root, given.FIXTURE_WORDS, Exemptions(allowlist=(entry,)))

    assert result.stale_entries == (entry,)


def test_an_unknown_pattern_id_in_the_exemptions_is_refused(tmp_path: Path):
    root = given.a_tree(tmp_path, {})

    entry = AllowedLine("docs/*.md", "no-such-word", "a line", "an entry naming no pattern")

    with pytest.raises(ValueError, match="no-such-word"):
        scan(root, given.FIXTURE_WORDS, Exemptions(allowlist=(entry,)))


def test_a_claude_md_without_the_glossary_line_is_refused(tmp_path: Path):
    root = given.a_tree(tmp_path, {"CLAUDE.md": "# Project\n\nSee docs/glossary.md.\n"})

    assert not imports_the_glossary(root)
