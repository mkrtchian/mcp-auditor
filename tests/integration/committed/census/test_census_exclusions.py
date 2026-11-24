from evals.cve.census.exclusions import ACCEPTANCE_TARGET_FLAWS
from evals.cve.detection.targets import ACCEPTANCE_TARGETS, OUT_OF_SCOPE_FLAWS


def test_every_current_and_dropped_acceptance_target_is_an_acceptance_target_flaw():
    targets = {target.flaw_id for target in (*ACCEPTANCE_TARGETS, *OUT_OF_SCOPE_FLAWS)}

    assert targets <= ACCEPTANCE_TARGET_FLAWS
