from dataclasses import replace

from tests.unit.detection.support.layouts import SOUND_LAYOUT
from tests.unit.support.acceptance_targets import FILESYSTEM, GIT, KUBERNETES, an_acceptance_target

# With no tools filter, which the detection holdout run refuses.
TARGETS = tuple(
    an_acceptance_target(flaw_id, tools_filter=None) for flaw_id in (FILESYSTEM, KUBERNETES, GIT)
)
BROKEN = replace(SOUND_LAYOUT, breaks=True)
LEAKING = replace(SOUND_LAYOUT, leaking=["container-hostname"])
