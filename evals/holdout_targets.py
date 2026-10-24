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
    cve_2025_11489_desktop_commander,
    cve_2025_66335_doris,
    cve_2026_2130_maigret,
    cve_2026_4270_aws_api_mcp,
    cve_2026_25546_godot_mcp,
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
)
