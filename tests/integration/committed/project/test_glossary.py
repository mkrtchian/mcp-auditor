import pytest

from evals.repository import REPO_ROOT
from tests.integration.committed.project.support.retired_word_exemptions import ALLOWLIST
from tests.integration.committed.project.support.retired_words import RETIRED_WORDS
from tests.unit.project.support.retired_word_scan import (
    Scan,
    imports_the_glossary,
    oversized_files,
    scan,
)

THE_ANDROID_DOCKERFILES = (
    "evals/docker/Dockerfile.android",
    "evals/docker/Dockerfile.holdout-2026-19978-android",
    "evals/docker/Dockerfile.holdout-2026-19978-android-patched",
    "evals/docker/Dockerfile.holdout-2026-81562-claude-in-mobile",
    "evals/docker/Dockerfile.holdout-2026-81562-claude-in-mobile-patched",
)


# Scanning the repository takes seconds, so its two tests share one scan.
@pytest.fixture(scope="module")
def repository_scan() -> Scan:
    return scan(REPO_ROOT, RETIRED_WORDS, ALLOWLIST)


def test_living_files_use_no_retired_word(repository_scan: Scan):
    assert repository_scan.violations == ()


def test_every_allowlist_entry_matches_a_line(repository_scan: Scan):
    assert repository_scan.stale_entries == ()


def test_the_size_bound_skips_only_the_files_embedding_an_android_capture():
    assert oversized_files(REPO_ROOT) == THE_ANDROID_DOCKERFILES


def test_claude_md_imports_the_glossary():
    assert imports_the_glossary(REPO_ROOT)
