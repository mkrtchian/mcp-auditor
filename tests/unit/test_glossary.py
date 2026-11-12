from pathlib import Path

import pytest

import tests.unit.support.test_glossary_given as given
from tests.unit.support.test_glossary_given import (
    REPO_ROOT,
    RETIRED_WORDS,
    AllowedLine,
    Exemptions,
    Scan,
    imports_the_glossary,
    scan,
)

# Pattern ids whose living hits the rule versions after the migration rename: the rule and log
# paths they catch change with those versions.
_NOT_YET_RENAMED = (
    "holdout-rule-log",
    "nuisance-rule-log",
)

# Living files the rule versions after the migration rewrite. The two logs stand for their
# living preambles, since their dated entries are never read.
_NOT_YET_MIGRATED = (
    "docs/holdout-rule.md",
    "docs/nuisance-rule.md",
    "docs/holdout-log.md",
    "docs/nuisance-log.md",
)

_ALLOWLIST = (
    AllowedLine(
        "docs/glossary.md",
        "bare-acceptance-server",
        '"holdout server" and "acceptance server" are always qualified',
        "the glossary quotes the bare words to forbid them",
    ),
    AllowedLine(
        "docs/glossary.md",
        "bare-holdout-server",
        '"holdout server" and "acceptance server" are always qualified',
        "the glossary quotes the bare words to forbid them",
    ),
    AllowedLine(
        "docs/glossary.md",
        "replay-retest",
        "where it is called the replay rule",
        "the glossary cites the name ADR 024 used",
    ),
    AllowedLine(
        "src/mcp_auditor/checkpointing.py",
        "missed-steps",
        '"refused_steps",',
        "an old channel name a resume across the migration is refused on",
    ),
    AllowedLine(
        "src/mcp_auditor/checkpointing.py",
        "missed-steps",
        '"missed_steps",',
        "an old channel name a resume across the migration is refused on",
    ),
    AllowedLine(
        "src/mcp_auditor/checkpointing.py",
        "missed-steps",
        '"chain_step_missed",',
        "an old channel name a resume across the migration is refused on",
    ),
    AllowedLine(
        "src/mcp_auditor/checkpointing.py",
        "judged-cases",
        '"judged_cases",',
        "an old channel name a resume across the migration is refused on",
    ),
    AllowedLine(
        "tests/unit/test_checkpointing.py",
        "missed-steps",
        '"missed_steps"',
        "the refusal cases name the old channels",
    ),
    AllowedLine(
        "tests/unit/test_checkpointing.py",
        "missed-steps",
        '"refused_steps",',
        "the refusal cases name the old channels",
    ),
    AllowedLine(
        "tests/unit/test_checkpointing.py",
        "missed-steps",
        '"chain_step_missed",',
        "the refusal cases name the old channels",
    ),
    AllowedLine(
        "tests/unit/test_checkpointing.py",
        "judged-cases",
        '"judged_cases",',
        "the refusal cases name the old channels",
    ),
    AllowedLine(
        "tests/unit/support/test_checkpointing_given.py",
        "audit-step",
        "OfAnEarlierVersion.__name__ = ",
        "writes a checkpoint under the class names of an earlier version",
    ),
    AllowedLine(
        "tests/integration/support/test_resume_earlier_checkpoint_given.py",
        "missed-steps",
        '"refused_steps"',
        "writes a checkpoint of an earlier version",
    ),
    AllowedLine(
        "tests/unit/test_rendering.py",
        "missed-steps",
        '"missed_steps"',
        "asserts that the product report carries none of the old keys",
    ),
    AllowedLine(
        "tests/unit/test_rendering.py",
        "eval-result",
        '"eval_result"',
        "asserts that the product report carries none of the old keys",
    ),
    AllowedLine(
        "tests/unit/test_rendering.py",
        "relayed-variables",
        '"relayed_variables"',
        "asserts that the product report carries none of the old keys",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "relayed-variables",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "evals/baseline.py",
        "replay-retest",
        'AliasChoices("retest_rule", "replay_rule")',
        "read alias of the committed honeypot baseline until its next re-recording",
    ),
    AllowedLine(
        "evals/judge/baseline.py",
        "replay-retest",
        'AliasChoices("retest_rule", "replay_rule")',
        "read alias of the committed judge baseline until its next re-recording",
    ),
    AllowedLine(
        "tests/unit/test_*baseline*.py",
        "replay-retest",
        "replay_rule",
        "the tests that a committed baseline loads through the alias",
    ),
    AllowedLine(
        "tests/unit/test_run_*.py",
        "ungated",
        '"--ungated"',
        "the CLI tests that the old flag is refused",
    ),
    AllowedLine(
        "tests/unit/test_run_*.py",
        "cve-flag",
        '"--cve"',
        "the CLI tests that the old flag is refused",
    ),
    AllowedLine(
        "tests/unit/test_run_*.py",
        "calibrate-cmd",
        '"--calibrate"',
        "the CLI tests that the old flag is refused",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "run-evals",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "e2e",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "judge-isolation",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "replay-retest",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "cve-id",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "run-cve-benchmark",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "cve-flag",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "calibrate-cmd",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "baselines-cve",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "moved-module",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "readmission",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "figure",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "miss-causes",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "not-run-conditions",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "eval-result",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "holdout-places",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "stand-in-target",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "ungated",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "holdout-calibration",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "CHANGELOG.md",
        "missed-steps",
        "(was ",
        "a rename entry names the word it replaces",
    ),
    AllowedLine(
        "evals/cve/census/work.py",
        "cve-id",
        "cve_id: str",
        "`VulnerableMcpEntry.cve_id` holds the CVE IDs vulnerablemcp.info lists",
    ),
    AllowedLine(
        "evals/cve/census/progress.py",
        "cve-id",
        "entry.cve_id",
        "reads of that field",
    ),
    AllowedLine(
        "tests/unit/support/test_census_given.py",
        "cve-id",
        "VulnerableMcpEntry(cve_id=",
        "builds that record",
    ),
    AllowedLine(
        "tests/unit/support/test_run_detection_holdout_run_given.py",
        "cve-id",
        "RETIRED_KEYS = ",
        "the old keys a holdout result and report no longer carry",
    ),
    AllowedLine(
        "tests/unit/support/test_run_detection_holdout_run_given.py",
        "primary-number",
        "RETIRED_KEYS = ",
        "the old keys a holdout result and report no longer carry",
    ),
    AllowedLine(
        "tests/unit/support/test_run_detection_holdout_run_given.py",
        "mechanism-class",
        "RETIRED_KEYS = ",
        "the old keys a holdout result and report no longer carry",
    ),
    AllowedLine(
        "tests/unit/support/test_run_detection_holdout_run_given.py",
        "miss-causes",
        "RETIRED_KEYS = ",
        "the old keys a holdout result and report no longer carry",
    ),
    AllowedLine(
        "tests/unit/test_run_*.py",
        "readmission",
        '"--readmission"',
        "the CLI tests that the old flag is refused",
    ),
    AllowedLine(
        "evals/cve/detection/holdout_fixtures/cve_2026_3484_nmap.py",
        "target-product",
        '"run_nmap_scan", {"target": ',
        "the `target` argument of run_nmap_scan, named by the audited server",
    ),
    AllowedLine(
        "evals/cve/nuisance/fix_checks/cve_2025_53100_codehooks.py",
        "target-product",
        '"file_upload": {"target": ',
        "the `target` argument of file_upload, named by the audited server",
    ),
    AllowedLine(
        "evals/cve/nuisance/fix_checks/cve_2025_53107_git_mcp.py",
        "target-product",
        '"target": "feature"',
        "the `target` argument of the git checkout tool, named by the audited server",
    ),
    AllowedLine(
        "evals/cve/nuisance/fix_checks/cve_2025_53107_git_mcp.py",
        "target-product",
        '"git_reset", {',
        "the `target` argument of git_reset, named by the audited server",
    ),
    AllowedLine(
        "evals/cve/nuisance/fix_checks/cve_2025_69256_serverless.py",
        "stub",
        "installer stub",
        "npm's own word for the package",
    ),
    AllowedLine(
        "evals/docker/Dockerfile.serverless*",
        "stub",
        "installer stub",
        "npm's own word for the package, in Dockerfile.serverless and Dockerfile.serverless-vuln",
    ),
)

_EXEMPTIONS = Exemptions(_NOT_YET_RENAMED, _NOT_YET_MIGRATED, _ALLOWLIST)


# Scanning the repository takes seconds, so its two tests share one scan.
@pytest.fixture(scope="module")
def repository_scan() -> Scan:
    return scan(REPO_ROOT, RETIRED_WORDS, _EXEMPTIONS)


def test_living_files_use_no_retired_word(repository_scan: Scan):
    assert repository_scan.violations == ()


def test_every_allowlist_entry_matches_a_line(repository_scan: Scan):
    assert repository_scan.stale_entries == ()


def test_claude_md_imports_the_glossary():
    assert imports_the_glossary(REPO_ROOT)


def test_a_retired_word_fires_on_a_living_file(tmp_path: Path):
    root = given.a_tree(tmp_path, {"evals/module.py": given.A_LINE_WITH_THE_WORD})

    result = scan(root, given.FIXTURE_WORDS, given.NO_EXEMPTION)

    assert given.hit_paths(result) == ["evals/module.py"]


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


def test_a_word_not_yet_renamed_is_skipped(tmp_path: Path):
    root = given.a_tree(tmp_path, {"src/module.py": given.A_LINE_WITH_THE_WORD})
    exemptions = Exemptions(not_yet_renamed=(given.THE_WORD_ID,))

    result = scan(root, given.FIXTURE_WORDS, exemptions)

    assert result.violations == ()


def test_a_file_not_yet_migrated_is_skipped(tmp_path: Path):
    root = given.a_tree(tmp_path, {"docs/holdout-rule.md": given.A_LINE_WITH_THE_WORD})
    exemptions = Exemptions(not_yet_migrated=("docs/holdout-rule.md",))

    result = scan(root, given.FIXTURE_WORDS, exemptions)

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

    with pytest.raises(ValueError, match="no-such-word"):
        scan(root, given.FIXTURE_WORDS, Exemptions(not_yet_renamed=("no-such-word",)))


def test_a_claude_md_without_the_glossary_line_is_refused(tmp_path: Path):
    root = given.a_tree(tmp_path, {"CLAUDE.md": "# Project\n\nSee docs/glossary.md.\n"})

    assert not imports_the_glossary(root)
