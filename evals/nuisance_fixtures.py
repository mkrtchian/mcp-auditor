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
    cve_2026_10276_jenkins,
    cve_2026_18905_contextforge,
    cve_2026_35402_neo4j_cypher,
    cve_2026_44336_praisonai,
    cve_2026_44694_n8n,
    cve_2026_46341_apify,
    cve_2026_47394_praisonai,
    cve_2026_55157_token_optimizer,
    cve_2026_55787_flyto,
    cve_2026_57442_mcpvault,
    cve_2026_58171_vibe_trading,
    cve_2026_65831_arcadedb,
    cve_2026_73844_ckan,
    cve_2026_73845_ckan,
    cve_2026_77252_atlassian,
    cve_2026_81562_claude_in_mobile,
    cve_2026_86439_knowns,
    ghsa_8g7g_hmwm_6rv2_n8n,
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
    *cve_2026_44694_n8n.TARGETS,
    *ghsa_8g7g_hmwm_6rv2_n8n.TARGETS,
    *cve_2026_86439_knowns.TARGETS,
    *cve_2026_57442_mcpvault.TARGETS,
    *cve_2026_58171_vibe_trading.TARGETS,
    *cve_2026_44336_praisonai.TARGETS,
    *cve_2026_47394_praisonai.TARGETS,
    *cve_2026_77252_atlassian.TARGETS,
    *cve_2026_46341_apify.TARGETS,
    *cve_2026_10276_jenkins.TARGETS,
    *cve_2026_35402_neo4j_cypher.TARGETS,
)
