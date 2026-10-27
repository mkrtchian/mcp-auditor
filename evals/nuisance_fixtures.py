"""The fix-check fixtures of the admitted nuisance servers, assembled from the per-flaw modules
under evals/nuisance_fix_checks/.

Each FixCheckTarget is what the fix check plants and reproduces on the vulnerable and patched
images, with its exploits and benign calls committed beside the admission. This module is the
thin aggregator, as evals/holdout_targets.py aggregates evals/holdout_fixtures/; the per-flaw
modules hold the callables and keep the kit's import closure.
"""

from evals.holdout_kit.fix_check import FixCheckTarget
from evals.nuisance_fix_checks import (
    cve_2025_53818_github_kanban,
    cve_2026_18905_contextforge,
    cve_2026_55157_token_optimizer,
    cve_2026_55787_flyto,
    cve_2026_65831_arcadedb,
    cve_2026_73844_ckan,
    cve_2026_73845_ckan,
    cve_2026_81562_claude_in_mobile,
)

FIX_CHECK_TARGETS: tuple[FixCheckTarget, ...] = (
    *cve_2025_53818_github_kanban.TARGETS,
    *cve_2026_55157_token_optimizer.TARGETS,
    *cve_2026_81562_claude_in_mobile.TARGETS,
    *cve_2026_55787_flyto.TARGETS,
    *cve_2026_65831_arcadedb.TARGETS,
    *cve_2026_73844_ckan.TARGETS,
    *cve_2026_73845_ckan.TARGETS,
    *cve_2026_18905_contextforge.TARGETS,
)
