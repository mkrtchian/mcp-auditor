from evals.cve.detection.holdout_targets import HOLDOUT_TARGETS
from evals.cve.detection.targets import ACCEPTANCE_TARGETS
from evals.cve.planting_base import STAND_IN_SERVICE


def test_a_target_declaring_a_stand_in_builds_the_stand_in_image():
    declaring = [
        target
        for target in (*ACCEPTANCE_TARGETS, *HOLDOUT_TARGETS)
        if target.planting_host.public_names.stand_ins
    ]

    assert not [target.flaw_id for target in declaring if STAND_IN_SERVICE not in target.images]
