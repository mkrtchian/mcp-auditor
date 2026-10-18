"""The drawn holdout targets: each is an acceptance CVETarget, which every instrument the holdout
run mode reuses (cve_calibration.check_target, cve_route, cve_layout_check,
cve_baseline.fixture_fingerprint) takes unchanged.

A CVETarget is not clean of mcp_auditor (its builder yields a cve_environments.Launch and its
exploits are typed on MCPClientPort); it does not need to be, since the holdout kit's isolation
test scans the kit, not this module.

HOLDOUT_TARGETS is empty until the maintainer's draw session fills it. No instrument module may
import this module (a unit test pins that), so a holdout flaw can never reach the acceptance gate,
the judge fixture draw or the probe corpus.
"""

from evals.cve_targets import CVETarget

HOLDOUT_TARGETS: tuple[CVETarget, ...] = ()
