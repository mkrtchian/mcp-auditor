"""Per-flaw fix-check fixtures of the admitted nuisance servers.

Each module carries the FixCheckFixture(s) of one server (its exploits and benign calls), the
counterpart of evals/cve/detection/holdout_fixtures/ for the fix check.
evals/cve/nuisance/fixtures.py aggregates them into FIX_CHECK_FIXTURES, as
evals/cve/detection/holdout_targets.py aggregates evals/cve/detection/holdout_fixtures/.

Every module here keeps the kit's import closure: it imports only from evals.cve.kit and the
clean evals.cve_* modules the kit rests on (cve_grammar, cve_places, cve_planting,
cve_planting_spec), never from mcp_auditor nor from evals.cve.environments.
"""
