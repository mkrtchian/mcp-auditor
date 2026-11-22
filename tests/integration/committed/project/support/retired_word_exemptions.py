"""Where the living text may still say a retired word, and why."""

from tests.unit.support.retired_word_scan import AllowedLine, Exemptions

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
        "tests/unit/auditor/test_checkpointing.py",
        "missed-steps",
        '"missed_steps"',
        "the refusal cases name the old channels",
    ),
    AllowedLine(
        "tests/unit/auditor/test_checkpointing.py",
        "missed-steps",
        '"refused_steps",',
        "the refusal cases name the old channels",
    ),
    AllowedLine(
        "tests/unit/auditor/test_checkpointing.py",
        "missed-steps",
        '"chain_step_missed",',
        "the refusal cases name the old channels",
    ),
    AllowedLine(
        "tests/unit/auditor/test_checkpointing.py",
        "judged-cases",
        '"judged_cases",',
        "the refusal cases name the old channels",
    ),
    AllowedLine(
        "tests/unit/auditor/support/test_checkpointing_given.py",
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
        "tests/unit/auditor/test_execution_rendering.py",
        "eval-result",
        '"eval_result"',
        "asserts that the product report carries none of the old keys",
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
        "tests/unit/evals/*test_*baseline*.py",
        "replay-retest",
        "replay_rule",
        "the tests that a committed baseline loads through the alias",
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
        "tests/unit/census/support/test_census_given.py",
        "cve-id",
        "VulnerableMcpEntry(cve_id=",
        "builds that record",
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
        '"target": "iss53"',
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
    AllowedLine(
        "docs/detection-suite-rule.md",
        "stub",
        "`stub`, `calibration`",
        "the rule lists the word among those a fixture may not carry",
    ),
    AllowedLine(
        "docs/nuisance-suite-rule.md",
        "stub",
        "benign, seed, stub, calibration",
        "the rule lists the word among those a fixture may not carry",
    ),
)

EXEMPTIONS = Exemptions(ALLOWLIST)
