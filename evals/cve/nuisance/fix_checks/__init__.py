"""Per-flaw fix-check fixtures of the admitted nuisance servers.

Each module carries the FixCheckFixture(s) of one server (its exploits and benign calls), the
counterpart of evals/cve/detection/holdout_fixtures/ for the fix check.
evals/cve/nuisance/fixtures.py aggregates them into FIX_CHECK_FIXTURES, as
evals/cve/detection/holdout_targets.py aggregates evals/cve/detection/holdout_fixtures/.

Every module here keeps the kit's import closure: it imports only from evals.cve.kit, the clean
evals.cve modules the kit rests on (the grammar, the places, the planting modules and what they
use), the sibling modules here and evals.cve.backends, never from mcp_auditor nor from
evals.cve.environments.
"""
