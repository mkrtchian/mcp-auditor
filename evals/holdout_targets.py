"""The drawn holdout targets, assembled from the per-target fixture modules under
evals/holdout_fixtures/. Each is an acceptance CVETarget, which every instrument the holdout run
mode reuses (cve_calibration.check_target, cve_route, cve_layout_check,
cve_baseline.fixture_fingerprint) takes unchanged.

A CVETarget is not clean of mcp_auditor (its builder yields a cve_environments.Launch and its
exploits are typed on MCPClientPort); it does not need to be, since the holdout kit's isolation
test scans the kit, not these modules.

No instrument module may import this module (a unit test pins that), so a holdout flaw can never
reach the acceptance gate, the judge fixture draw or the probe corpus.
"""

from evals.cve_targets import CVETarget
from evals.holdout_fixtures import (
    cve_2025_9654_mcp_ssh,
    cve_2025_11489_desktop_commander,
    cve_2025_53818_github_kanban,
    cve_2025_58358_markdownify,
    cve_2025_66335_doris,
    cve_2026_2130_maigret,
    cve_2026_3484_nmap,
    cve_2026_3680_biome,
    cve_2026_4270_aws_api_mcp,
    cve_2026_5323_a11y,
    cve_2026_5602_heim,
    cve_2026_5603_magento2,
    cve_2026_5833_taskwarrior,
    cve_2026_7785_wireshark,
    cve_2026_18905_contextforge,
    cve_2026_19978_android,
    cve_2026_25546_godot_mcp,
    cve_2026_26029_sf_mcp,
    cve_2026_33060_ckan,
    cve_2026_42260_open_websearch,
    cve_2026_45555_roslyncodelens,
    cve_2026_55581_mcp_shell,
    cve_2026_55787_flyto,
    cve_2026_58485_searxng,
    cve_2026_65831_arcadedb,
    cve_2026_85788_mysql,
    cve_2026_104120_fetch,
    ghsa_8g7g_hmwm_6rv2_n8n,
)

HOLDOUT_TARGETS: tuple[CVETarget, ...] = (
    cve_2026_4270_aws_api_mcp.TARGET,
    cve_2026_2130_maigret.TARGET,
    cve_2026_104120_fetch.TARGET,
    cve_2026_85788_mysql.TARGET,
    cve_2026_25546_godot_mcp.TARGET,
    cve_2025_11489_desktop_commander.TARGET,
    cve_2025_66335_doris.TARGET,
    ghsa_8g7g_hmwm_6rv2_n8n.TARGET,
    cve_2026_65831_arcadedb.TARGET,
    cve_2026_45555_roslyncodelens.TARGET,
    cve_2026_5323_a11y.TARGET,
    cve_2026_33060_ckan.TARGET,
    cve_2026_55787_flyto.TARGET,
    cve_2026_58485_searxng.TARGET,
    cve_2026_42260_open_websearch.TARGET,
    cve_2026_18905_contextforge.TARGET,
    cve_2026_7785_wireshark.TARGET,
    cve_2025_9654_mcp_ssh.TARGET,
    cve_2026_19978_android.TARGET,
    cve_2026_55581_mcp_shell.TARGET,
    cve_2025_58358_markdownify.TARGET,
    cve_2026_5603_magento2.TARGET,
    cve_2025_53818_github_kanban.TARGET,
    cve_2026_5833_taskwarrior.TARGET,
    cve_2026_26029_sf_mcp.TARGET,
    cve_2026_3484_nmap.TARGET,
    cve_2026_3680_biome.TARGET,
    cve_2026_5602_heim.TARGET,
)
