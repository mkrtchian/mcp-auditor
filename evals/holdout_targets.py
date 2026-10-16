"""The format and loader of a drawn holdout target: a composition over the acceptance CVETarget
plus the side the draw placed it on.

HoldoutTarget wraps a CVETarget rather than duplicating its fields, so every instrument the
holdout run mode reuses (cve_calibration.check_target, cve_route, cve_layout_check,
cve_baseline.fixture_fingerprint) takes `entry.target` unchanged, with no Protocol over two types
and no duplication. The composed CVETarget is not clean of mcp_auditor (its builder yields a
cve_environments.Launch and its exploits are typed on MCPClientPort); it does not need to be, since
the holdout kit's isolation test scans the kit, not this module.

HOLDOUT_TARGETS is empty until the maintainer's draw session fills it. Nothing imports it yet: the
holdout run mode is a later plan. No instrument module may import this module (a unit test pins
that), so a holdout flaw can never reach the acceptance gate, the judge fixture draw or the probe
corpus.
"""

from dataclasses import dataclass

from evals.census_draw import Side
from evals.cve_targets import CVETarget


@dataclass(frozen=True)
class HoldoutTarget:
    target: CVETarget
    side: Side

    @property
    def identifier(self) -> str:
        return self.target.cve_id


HOLDOUT_TARGETS: tuple[HoldoutTarget, ...] = ()
