"""Where the living text may still say a retired word, and why."""

from tests.unit.support.retired_word_scan import AllowedLine, Exemptions

# Pattern ids whose living hits the rule versions after the migration rename: the rule and log
# paths they catch change with those versions.
NOT_YET_RENAMED = (
    "holdout-rule-log",
    "nuisance-rule-log",
)

# Living files the rule versions after the migration rewrite. The two logs stand for their
# living preambles, since their dated entries are never read.
NOT_YET_MIGRATED = (
    "docs/holdout-rule.md",
    "docs/nuisance-rule.md",
    "docs/holdout-log.md",
    "docs/nuisance-log.md",
)

ALLOWLIST = (
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

EXEMPTIONS = Exemptions(NOT_YET_RENAMED, NOT_YET_MIGRATED, ALLOWLIST)
