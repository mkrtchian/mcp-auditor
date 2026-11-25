"""Per-flaw fix-check fixtures of the admitted nuisance servers.

Each module carries the FixCheckFixture(s) of one server (its exploits and benign calls), apart
from a few shared helpers that several fixtures import and that carry none, the counterpart of
evals/cve/detection/holdout_fixtures/ for the fix check.
evals/cve/nuisance/fixtures.py aggregates them into FIX_CHECK_FIXTURES, as
evals/cve/detection/holdout_targets.py aggregates evals/cve/detection/holdout_fixtures/.

Every module here stays free of mcp_auditor and evals.cve.environments: beyond the standard
library, it imports only from evals.cve.kit, the clean evals.cve modules the kit rests on (the
grammar, the places, the planting modules and what they use), evals.cve.docker_paths,
evals.cve.backends and the sibling modules here.
"""
