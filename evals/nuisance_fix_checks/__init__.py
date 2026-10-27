"""Per-flaw fix-check fixtures of the admitted nuisance servers.

Each module carries the FixCheckTarget(s) of one server (its exploits and benign calls), the
twin of evals/holdout_fixtures/ for the fix check. evals/nuisance_fixtures.py aggregates them
into FIX_CHECK_TARGETS, as evals/holdout_targets.py aggregates evals/holdout_fixtures/.

Every module here keeps the kit's import closure: it imports only from evals.holdout_kit and the
clean evals.cve_* modules the kit rests on (cve_grammar, cve_places, cve_planting,
cve_planting_spec), never from mcp_auditor nor from evals.cve_environments.
"""
