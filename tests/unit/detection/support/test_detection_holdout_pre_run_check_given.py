from dataclasses import replace

from tests.unit.detection.support.layouts import SOUND_LAYOUT
from tests.unit.support import detection_holdout_runs
from tests.unit.support.acceptance_targets import FILESYSTEM, GIT, KUBERNETES

TARGETS = tuple(
    detection_holdout_runs.a_target(flaw_id) for flaw_id in (FILESYSTEM, KUBERNETES, GIT)
)
BROKEN = replace(SOUND_LAYOUT, breaks=True)
LEAKING = replace(SOUND_LAYOUT, leaking=["container-hostname"])
